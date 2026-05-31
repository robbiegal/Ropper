# coding=utf-8
# Tests for the ret2libc spawn_shell (system('/bin/sh')) ropchain generator
# across x86, x86_64 and ARM.
import re
import unittest

from ropper.service import RopperService
from ropper.common.error import RopperError
from ropper.ropchain.ropchain import RopChain


_BINARIES = {
    'x86': 'test-binaries/ls-x86',
    'x86_64': 'test-binaries/ls-x86_64',
    'ARM': 'test-binaries/ls-arm',
}


def _service(arch):
    rs = RopperService(options={'all': False, 'type': 'all', 'inst_count': 6})
    path = _BINARIES[arch]
    rs.addFile(path, arch=arch)
    rs.loadGadgetsFor(path)
    return rs, path


def _generate(arch, options=None):
    rs, path = _service(arch)
    return rs.createRopChain('spawn_shell', arch, options=options or {})


def _generator(arch):
    """Construct the generator object directly so the resolver helpers can be
    exercised in isolation."""
    rs, path = _service(arch)
    fc = rs.getFileFor(path)
    return RopChain.get([fc.loader], {fc.loader: fc.gadgets}, 'spawn_shell', None, b'')


class SpawnShellCommon(unittest.TestCase):
    """Architecture-agnostic guarantees, run for every supported arch."""

    def test_arch_is_supported(self):
        for arch in _BINARIES:
            try:
                chain = _generate(arch, {'cmd': '/bin/sh'})
            except RopperError as e:
                self.fail('spawn_shell raised RopperError for %s: %s' % (arch, e))
            self.assertIn('rop = ', chain, arch)

    def test_emits_runnable_skeleton(self):
        for arch in _BINARIES:
            chain = _generate(arch)
            self.assertIn('from struct import pack', chain, arch)
            self.assertIn("rop = ''", chain, arch)
            self.assertIn('print(rop)', chain, arch)

    def test_supplied_addresses_are_used_verbatim_not_rebased(self):
        # address= (libc system) and string= (&"/bin/sh") are absolute runtime
        # addresses, so they must be emitted through plain p(), never rebased.
        for arch in _BINARIES:
            chain = _generate(arch, {'address': '0xf7c4d3e0', 'string': '0xcafe0000'})
            # Value width is arch-dependent (zero-padded to 4 or 8 bytes), so
            # assert on the significant hex digits rather than exact formatting.
            self.assertIn('SYSTEM_ADDR =', chain, arch)
            self.assertIn('f7c4d3e0', chain, arch)
            self.assertIn('BINSH_ADDR =', chain, arch)
            self.assertIn('cafe0000', chain, arch)
            self.assertIn('rop += p(SYSTEM_ADDR)', chain, arch)
            self.assertIn('rop += p(BINSH_ADDR)', chain, arch)
            # A supplied string must never trigger a .data write.
            self.assertNotIn('written to .data', chain, arch)
            self.assertNotIn("rop += '", chain, arch)

    def test_missing_system_falls_back_to_placeholder(self):
        # None of the ls-* test binaries define or import system(), so the
        # generator must degrade to a clearly-labelled placeholder.
        for arch in _BINARIES:
            chain = _generate(arch)
            self.assertIn('SYSTEM_ADDR = 0xdeadbeef', chain, arch)
            self.assertIn('TODO', chain, arch)


class SpawnShellX86(unittest.TestCase):

    def test_cdecl_layout_order(self):
        # cdecl: [&system][return addr][&cmd] - system must precede the arg.
        chain = _generate('x86', {'address': '0x11112222', 'string': '0x33334444'})
        sys_pos = chain.index('rop += p(SYSTEM_ADDR)')
        arg_pos = chain.index('rop += p(BINSH_ADDR)')
        self.assertLess(sys_pos, arg_pos)
        self.assertIn('return address', chain)


class SpawnShellX86_64(unittest.TestCase):

    def test_uses_pop_rdi_and_alignment_ret(self):
        chain = _generate('x86_64', {'address': '0x11112222', 'string': '0x33334444'})
        # ls-x86_64 ships a `pop rdi ; ret`.
        self.assertIn('pop rdi', chain)
        # rdi (arg) is loaded before the call to system.
        self.assertLess(chain.index('pop rdi'), chain.index('rop += p(SYSTEM_ADDR)'))
        # Stack alignment ret is added by default for glibc movaps.
        self.assertIn('stack alignment', chain)

    def test_align_false_skips_alignment_ret(self):
        chain = _generate('x86_64', {'address': '0x11112222', 'align': 'false'})
        self.assertNotIn('16-byte stack alignment for glibc', chain)


class SpawnShellARM(unittest.TestCase):

    def test_emits_placeholder_when_no_r0_pop(self):
        # ls-arm has no `pop {r0, .., pc}` gadget, so a placeholder with the
        # intended r0/pc slots must be emitted rather than raising.
        chain = _generate('ARM', {'address': '0x11112222', 'string': '0x33334444'})
        self.assertIn('INSERT `pop {r0, pc}` GADGET HERE', chain)
        self.assertIn('intended for r0', chain)
        self.assertIn('intended for pc', chain)


class SpawnShellResolvers(unittest.TestCase):
    """Direct coverage of the shared symbol/import resolution helpers."""

    def test_imported_symbol_reports_got_slot_but_no_definition(self):
        for arch in _BINARIES:
            gen = _generator(arch)
            # strlen is imported by every ls-* binary.
            self.assertIsNotNone(gen._findImportGotSlot('strlen'), arch)
            # ...but it is not *defined* inside the binary.
            self.assertIsNone(gen._findSymbolAddress('strlen'), arch)

    def test_unknown_symbol_resolves_to_none(self):
        for arch in _BINARIES:
            gen = _generator(arch)
            self.assertIsNone(gen._findImportGotSlot('totally_not_a_symbol_zzz'), arch)
            self.assertIsNone(gen._findSymbolAddress('totally_not_a_symbol_zzz'), arch)

    def test_missing_string_resolves_to_none(self):
        for arch in _BINARIES:
            gen = _generator(arch)
            self.assertIsNone(gen._findExistingString('this string is not present zzz'), arch)


class SpawnShellRegression(unittest.TestCase):
    """Regression coverage for defects found during review."""

    def test_data_buffer_pointer_resolves_to_the_written_address(self):
        # Defect: the .data branch routed an already-image-base-relative offset
        # through _rebaseLine(), which subtracted the image base a second time,
        # so the "/bin/sh" pointer landed `imageBase` bytes away from where the
        # string was actually written.  The pointer must rebase exactly to the
        # .data buffer (== section.virtualAddress).  Force the write branch with
        # a stub so the test does not depend on a write-what-where gadget.
        for arch in _BINARIES:
            gen = _generator(arch)
            gen._writeCmdToData = lambda cmd, dataaddr: "rop += 'STUB-WRITE'\n"
            line, defs, write_text = gen._resolveBinshPointer('/bin/sh', None)
            self.assertIn('written to .data', line, arch)
            self.assertEqual('', defs, arch)
            self.assertIn('STUB-WRITE', write_text, arch)
            m = re.search(r'rebase_\d+\((0x[0-9a-fA-F]+)\)', line)
            self.assertIsNotNone(m, '%s: %r' % (arch, line))
            emitted_off = int(m.group(1), 16)
            section = gen._binaries[0].getSection('.data')
            self.assertEqual(emitted_off + gen._binaries[0].imageBase,
                             section.virtualAddress, arch)

    def test_x86_64_padding_counts_extended_registers(self):
        # Defect: _paddingNeededFor's `^pop (...)$` matched exactly three chars,
        # silently dropping `pop r8` / `pop r9`, which under-padded the chain and
        # let the extra pop swallow the next chain word.
        gen = _generator('x86_64')

        class _FakeGadget(object):
            lines = [(0, 'pop rdi'), (4, 'pop r8'), (8, 'pop r9'), (12, 'pop r15'), (16, 'ret')]

        self.assertEqual(gen._paddingNeededFor(_FakeGadget()), ['r8', 'r9', 'r15'])


if __name__ == '__main__':
    unittest.main()
