# SPDX-License-Identifier: GPL-2.0-or-later
"""Require the requested body presses and native recovery before playback."""
from copy import deepcopy
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.body_shutter_gate_probe import post_capture_playback_ready


def check():
    application = dict(index=3)
    first = dict(body_repeat_capture=dict(shots=[dict(released=True)]),
        shutter_click=dict(released=True),
        after=dict(capture_state=[2, 0], capture_driver_state=9, status_codes=[]))
    assert post_capture_playback_ready(first, application, 1)
    assert not post_capture_playback_ready(first, application, 2), 'One press satisfied a repeated capture'
    repeated = deepcopy(first)
    repeated['body_repeat_capture']['shots'].append(dict(released=True))
    assert post_capture_playback_ready(repeated, application, 2)
    assert not post_capture_playback_ready(repeated, application, 1)
    for count in (0, 1):
        trace = deepcopy(repeated)
        trace['body_repeat_capture']['shots'] = trace['body_repeat_capture']['shots'][:count]
        assert not post_capture_playback_ready(trace, application, 2)
    for index in (0, 1):
        trace = deepcopy(repeated)
        trace['body_repeat_capture']['shots'][index]['released'] = False
        assert not post_capture_playback_ready(trace, application, 2), 'A held contact admitted playback'
    for field, value in (('capture_state', [8, 0]), ('capture_driver_state', 15), ('status_codes', [68])):
        trace = deepcopy(repeated)
        trace['after'][field] = value
        assert not post_capture_playback_ready(trace, application, 2)
    trace = deepcopy(repeated)
    trace['shutter_click']['released'] = False
    assert not post_capture_playback_ready(trace, application, 2)
    assert not post_capture_playback_ready(repeated, dict(index=2), 2)
    print('PASS post-capture playback requires all requested releases and native shooting recovery')


if __name__ == '__main__':
    check()
