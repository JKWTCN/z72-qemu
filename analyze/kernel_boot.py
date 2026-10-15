# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode the original syscall handoff that follows the parameter tail."""
from analyze.decode_z72 import BASE, digest, require
from analyze.firmware_structure import u32

SVC_CLASS = 6
STAGE_WINDOW = 0xBAB00000
STAGE_BYTES = 0x100000
# Private RAM holding the wait objects the handoff blocks on.
WAIT_RAM = {'master': (0xB1800000, 0xB7D00000), 'slave': (0xC1000000, 0xC6100000)}
# Mailbox window watched to exclude a direct poll at this stage.
MESSAGE = {'master': 0xB7C00000, 'slave': 0xC6000000}
# Stand-in value substituting the unmodeled peer-engine response.
RELEASE_VALUE = 1
# Structural boundary both roles reach when the handoff completes and
# execution continues past every registered word: a second-level page-table
# gap at 0x2C020000 that no device registration can honestly cross. Longer
# exploratory runs additionally dereference the stand-in value as a pointer
# (1+0x33 -> 0x34, domain fault) and fault at 0x0428002C.
PEER_BOUNDARY = (0x8, 0x2C020000)

# Verified stock code windows are pinned by file offset, length and SHA-256.
# The original instruction bytes are not redistributed with this project.
# Window notes: the master wrapper/veneer pair, the staging call continuation,
# the copied payload header/vector block, and the payload store veneer that
# the wait path re-enters. Slave windows cover the handoff wrapper, the SWI
# veneer, the class dispatcher and the indexed wait loop.
_MASTER = dict(
    chain_return=0x1E0042,
    staging_entry=0x348290,
    staging_call=0x3482A4,
    staging_continuation=0x3482A8,
    wrapper_thumb=0x32FA20,
    wrapper_arm=0xE3FE0,
    svc_instruction=0xE3FF4,
    descriptor=0x010B0211,
    descriptor_at=0xE4004,
    payload_file=0xE0000,
    payload_bytes=0x21538,
    payload_words=(0x1002BC88, 0x10103560, 0x101036A8),
    swi_vector=0x10100008,
    release_word=0xB2C59A90,
    windows=(
        (0x32FA20, 8, 'bc6420d66e63bde8671686230a6c17dc3a31009afbc76c438bcc318d4629b5c3'),
        (0xE3FE0, 0x28, 'edd318e1fac1ca10db438622e7b798d5c1195eba32eb07bc113e07c7919bd372'),
        (0x3482A4, 14, '00b6a68c5345022adeab57f322e771b3beab960dc1adf074bb5d849c02a71fea'),
        (0xE0000, 44, '5ac8b094f4ce8a20c8c5a65d3ad0d7b1836ca476eed0d84826801ff64efffb62'),
        (0x10042C, 16, 'a635ebbbac57282990f8898354a72d2e470506a5f3ef4f26007368a6ea3280ed')))

_SLAVE = dict(
    chain_return=0x32F82,
    release_word=0xC19B4FC8,
    wrapper_arm=0x15FA0,
    svc_instruction=0x15FAC,
    descriptor=0x80430200,
    descriptor_at=0x15FBC,
    swi_veneer=0x14108,
    swi_veneer_target=0x10035010,
    dispatcher=0x15010,
    dispatcher_table=0x15044,
    dispatcher_class_handler=0x10038FF8,
    handler_low=0x14000,
    handler_high=0x40000,
    wait_load=0x1903C,
    windows=(
        (0x15F9C, 2, '707bf0b938f307b5c222e670598b865d5e1f8a8003df82c7abbf7c9f8fa4d720'),
        (0x15FA0, 0x20, '85c39d9f60c15c5b9d4bdf3adcc3df84d2a80d43a4acaef92679d16c6802e78c'),
        (0x14108, 4, '943a1ab95bd7f6a6c737e42510ba6b592eb2186a25df0bd2599849675b36b07a'),
        (0x14124, 4, '859409224e6d2e984f48aa321cf70208e891c2d70a60ca009e07ed2ef931ce9f'),
        (0x15010, 0x40, '8d0caafe411e157da4bfcfc64519b280fc748af3e394ed12b446021792cfffd7'),
        (0x19038, 16, 'e70bf8775f50f23db7c072db97a521a9467189fa5873708d374cd084fa4158f3')))


def kernel_profile(image, structure, role):
    """Verify the syscall-handoff code windows and return the stage profile."""
    require(role in ('master', 'slave'), 'Unsupported firmware role')
    profile = _MASTER if role == 'master' else _SLAVE
    for offset, length, window_sha in profile['windows']:
        require(digest(image[offset:offset + length]) == window_sha,
                'Unsupported kernel handoff code window')
    result = dict(role=role, chain_return=profile['chain_return'],
                  svc_instruction=profile['svc_instruction'],
                  descriptor=profile['descriptor'], svc_class=SVC_CLASS)
    if role == 'master':
        require(u32(image, profile['descriptor_at']) == profile['descriptor'] and
                u32(image, profile['payload_file']) == 0xE59FF018 and
                u32(image, profile['payload_file']+0x20) == profile['payload_words'][0] and
                u32(image, profile['payload_file']+0x24) == profile['payload_words'][1] and
                u32(image, profile['payload_file']+0x28) == profile['payload_words'][2],
                'Unsupported payload vector layout')
        result.update(staging_entry=profile['staging_entry'],
                      staging_call=profile['staging_call'],
                      staging_continuation=profile['staging_continuation'],
                      wrapper_thumb=profile['wrapper_thumb'],
                      wrapper_arm=profile['wrapper_arm'],
                      payload=dict(source_file=profile['payload_file'],
                                   length=profile['payload_bytes'],
                                   dest=STAGE_WINDOW, window=STAGE_BYTES),
                      payload_words=profile['payload_words'],
                      handler_low=BASE+profile['payload_file'],
                      handler_high=BASE+profile['payload_file']+profile['payload_bytes'],
                      wait_ram=WAIT_RAM['master'], message=MESSAGE['master'],
                      release_word=profile['release_word'],
                      next_fault=PEER_BOUNDARY,
                      swi_vector=profile['swi_vector'])
    else:
        require(u32(image, profile['descriptor_at']) == profile['descriptor'] and
                u32(image, profile['swi_veneer']+0x1C) == profile['swi_veneer_target'] and
                u32(image, profile['dispatcher_table']+8) == profile['dispatcher_class_handler'],
                'Unsupported slave dispatcher layout')
        result.update(wrapper_arm=profile['wrapper_arm'],
                      swi_veneer=profile['swi_veneer'],
                      swi_veneer_target=profile['swi_veneer_target'],
                      dispatcher=profile['dispatcher'],
                      dispatcher_table=profile['dispatcher_table'],
                      dispatcher_class_handler=profile['dispatcher_class_handler'],
                      handler_low=BASE+profile['handler_low'],
                      handler_high=BASE+profile['handler_high'],
                      wait_load=profile['wait_load'],
                      wait_ram=WAIT_RAM['slave'], message=MESSAGE['slave'],
                      release_word=profile['release_word'],
                      next_fault=PEER_BOUNDARY)
    return result
