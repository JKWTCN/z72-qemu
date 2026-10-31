# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe original full-release gating or playback capture-stop requests (C 1.70)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from analyze.qemu_display import Remote
from tools.web_console import Machine

ACTION = 0x1053ba0e
ENGINE_ABORT_POINTS = {
    0x1010000c: 'execution-prefetch-abort',
    0x10100010: 'execution-data-abort',
    0x1003410c: 'slave-execution-prefetch-abort',
    0x10034110: 'slave-execution-data-abort',
}
AFTER_ACTION = {
    0x10542038: 'action-check-result',
    0x104e6c28: 'release-gate-result',
    0x104e6c66: 'past-release-gate',
    0x104e6c70: 'release-action-qualification-result',
    0x105548e2: 'release-action-context-check',
    0x105548ec: 'release-action-property-check',
    0x10554902: 'release-action-qualification-return',
    0x104e16b4: 'release-action-configuration-entry',
    0x104e1714: 'release-action-configuration-return',
    0x104e1910: 'release-action-configuration-timer-choice',
    0x10542064: 'body-action-state-check',
    0x10542070: 'body-action-mode-result',
    0x10542076: 'body-action-condition-result',
    0x10542368: 'body-action-fallback-check',
    0x1054238a: 'body-action-flags-choice',
    0x10542394: 'body-action-normal-route',
    0x104e63ae: 'body-action-dispatch',
    0x105af1dc: 'body-action-callback-dispatch',
    0x104e6cb4: 'body-action-state-update',
    0x1053e598: 'event1-check-result',
    0x1053e62c: 'release-gate-clear-path',
}
BODY_CONFIGURATION_POINTS = {
    0x1052273e: 'body-configuration-submit',
    0x10635cf6: 'body-configuration-wrapper',
    0x104847c2: 'body-configuration-list',
    0x10484800: 'body-configuration-node-call',
    0x10484802: 'body-configuration-node-return',
    0x1048480a: 'body-configuration-cancel-check',
    0x104e1824: 'body-configuration-first-result',
    0x104e1850: 'body-configuration-second-result',
    0x104e188e: 'body-configuration-loop-complete',
}
BODY_STATE_POINTS = {
    0x104e6cb4: 'body-action-state-update',
    0x104e6ce4: 'body-state-input-query-result',
    0x104e6d4a: 'body-state-context-query-result',
    0x104e6d52: 'body-state-context-check-result',
    0x104e6d60: 'body-state-control-query-result',
    0x104e6d76: 'body-state-property180b-result',
    0x104e6dc8: 'body-state-property-fallback',
    0x104e6dee: 'body-state-alternate-path',
    0x104e6e16: 'body-state-context-fallback',
    0x104e6e5e: 'body-state-final-mode-result',
    0x104e6e68: 'body-state-final-option8-result',
    0x104e6e7c: 'body-state-notification',
    0x10551cf2: 'body-state-input-handler',
    0x1055363e: 'body-state-context-handler',
}
BODY_STATUS_POINTS = {
    0x10299c18: 'body-status-core-conversion',
    0x102a4b26: 'body-status-core-forward',
    0x106d1e30: 'body-status-request',
    0x106d1ed2: 'body-status-store',
    0x106d0a52: 'body-status-worker-flags',
    0x106d13de: 'body-status-event',
    0x106d2104: 'body-status-property-update',
    0x106d2122: 'body-status-property-set',
    0x106d2126: 'body-status-property-set-return',
}
BODY_CAPTURE_POINTS = {
    0x1022827c: 'body-capture-operation-registration',
    0x103e7312: 'body-capture-state-request',
}
BODY_CAPTURE_CONFIGURATION_POINTS = {
    address: BODY_CONFIGURATION_POINTS[address] for address in
    (0x1052273e, 0x10635cf6, 0x104847c2, 0x10484800,
     0x104e1824, 0x104e1850, 0x104e188e)
} | {0x1048481e: 'body-configuration-list-result'}
BODY_INPUT_POINTS = {
    0x102a4794: 'body-input-before-foreground-dispatch',
    0x102a47ba: 'body-input-change-result',
    0x102a47c4: 'body-input-enqueue-result',
    0x1029ee9c: 'body-input-worker-dequeue-result',
}
BODY_COMPUTE_POINTS = {
    0x102449a0: 'body-master-compute-entry',
    0x102449c4: 'body-master-compute-initialized',
    0x10243bf8: 'body-master-compute-request-ack-wait',
    0x102449da: 'body-master-compute-submit-return',
    0x102449ec: 'body-master-compute-result-wait-return',
    0x10244910: 'body-master-compute-result-callback',
}
BODY_SYSTEM_POINTS = {
    0x1029993e: 'body-system-foreground-input',
    0x102a6984: 'body-system-base-mode-input',
    0x10245f5e: 'body-system-policy-mode-input',
    0x10247ad0: 'body-system-forward-mode-input',
    0x102a6970: 'body-system-notification',
    0x1020dad2: 'body-system-base-notification',
    0x1020d384: 'body-system-mode-request',
}
CAPTURE_INPUT_POINTS = {
    0x1020aafc: 'capture-input-enable-entry',
    0x1020ab00: 'capture-input-enable-return',
    0x1020a830: 'capture-input-disable-entry',
    0x1020a834: 'capture-input-disable-return',
    0x1020ab3c: 'capture-input-hard-stop-entry',
    0x1020ab40: 'capture-input-hard-stop-return',
    0x1023938c: 'capture-primary-input-callback',
    0x10238d4a: 'capture-input-task-event',
    0x10238c40: 'capture-input-completed-dequeue',
    0x10321d80: 'capture-input-driver-complete',
    0x10321d94: 'capture-input-driver-output-check',
    0x10321dbe: 'capture-input-driver-output-enqueue',
    0x10325304: 'capture-image-context-initialize',
    0x10326280: 'capture-alternate-context-entry',
    0x103262e8: 'capture-alternate-context-ready',
    0x1032642e: 'capture-staged-context-entry',
    0x10326468: 'capture-staged-context-allocation-return',
    0x10326476: 'capture-staged-context-parameter-check-return',
    0x10326486: 'capture-staged-context-mode-check-return',
    0x10326546: 'capture-staged-context-ready',
    0x10326608: 'capture-staged-work-condition',
    0x10326620: 'capture-staged-work-submit',
    0x10326624: 'capture-staged-work-submit-return',
    0x103d0df0: 'capture-work-mode-condition',
    0x103d0e00: 'capture-work-mode-rejected',
    0x103d0eae: 'capture-work-request-allocation-entry',
    0x103d1132: 'capture-work-request-registration-return',
    0x10262e64: 'capture-processing-result-event-producer',
    0x103bde3e: 'capture-output-status-dispatch',
    0x10448496: 'capture-display-deferred',
    0x104484de: 'capture-display-applied',
    0x104d7596: 'capture-display-mode-check',
    0x10448e92: 'capture-display-reset-before',
    0x10448e96: 'capture-display-reset-after',
    0x10264f5c: 'capture-processing-release-entry',
    0x10265120: 'capture-processing-release-notification-condition',
    0x103cdb26: 'capture-processing-release-notification',
    0x102639d6: 'capture-stop-first-message-event',
    0x102642a4: 'capture-stop-second-message-event',
    0x10263820: 'capture-stop-first-aggregate-wait-return',
    0x102642c6: 'capture-stop-second-aggregate-wait-return',
    0x10369fc4: 'capture-image-stop-command',
    0x102e4548: 'capture-image-control-first-wait',
    0x102e455c: 'capture-image-control-command-check-return',
    0x102e4570: 'capture-image-control-second-wait',
    0x102e4574: 'capture-image-control-second-wait-return',
    0x103231b2: 'capture-driver-state-update',
    0x103e6e94: 'capture-state-update',
    0x103b93d0: 'capture-release-stop-entry',
    0x103b940a: 'capture-release-stop-state-updated',
    0x103b9538: 'capture-release-signal',
    0x103b9184: 'capture-release-completion-notification',
    0x103ba1cc: 'capture-release-phase-request',
    0x103ba1d0: 'capture-release-phase-request-return',
    0x103ba29c: 'capture-release-phase-result',
    0x103b9848: 'capture-release-count-notification',
    0x103b9826: 'capture-release-count-updated',
    0x10238d64: 'capture-input-task-before-dequeue',
    0x10238d02: 'capture-input-task-after-disable',
    0x1023c6ec: 'capture-input-task10-consumer',
    0x1023beec: 'capture-input-completed-enqueue',
    0x103cc8e8: 'capture-image-tracking-enqueue-mode2',
    0x1022e2e0: 'capture-input-tail-notification',
    0x1022ff42: 'capture-input-tail-worker-parameter-check',
    0x10230052: 'capture-input-tail-driver-notification',
    0x1032ac52: 'capture-input-parameter-clone',
    0x1032ac9a: 'capture-input-parameter-clone-ready',
    0x1031a690: 'capture-input-parameter-copy',
    0x1031a638: 'capture-input-parameter-initialize',
    0x10360468: 'capture-input-tail-configuration-build',
    0x103604ca: 'capture-input-tail-configuration-result',
    0x103eb2e4: 'capture-request-variant-selection',
    0x10326eee: 'capture-metadata-condition',
    0x10326ff0: 'capture-metadata-skip-body',
    0x1032729a: 'capture-metadata-stage-submit',
    0x102b3362: 'capture-jpeg-job-build',
    0x1026a312: 'capture-jpeg-worker-entry',
    0x1026a448: 'capture-jpeg-worker-output-allocation-return',
    0x1026a4ba: 'capture-jpeg-worker-first-submit',
    0x1026a5f8: 'capture-jpeg-worker-second-submit',
    0x1031eabe: 'capture-driver-input-flags-entry',
    0x1031ead8: 'capture-driver-input-flags-stored',
    0x1031cb20: 'capture-driver-stop-flags-entry',
    0x1032ae3c: 'capture-driver-input-mask-release',
    0x1031e83e: 'capture-input-aggregate-task',
    0x1031e602: 'capture-input-selection-return',
    0x1031e778: 'capture-input-selected-prepare',
    0x1031e77e: 'capture-input-selected-submit',
    0x1031e782: 'capture-input-selected-submit-return',
    0x1031e80a: 'capture-input-selection-empty',
    0x103ce6ac: 'capture-still-input-entry',
    0x103ce318: 'capture-still-job-build',
    0x103ce528: 'capture-still-job-submit',
    0x103ce434: 'capture-still-job-queue',
    0x103ce574: 'capture-still-job-build-finish',
    0x102c8f4e: 'capture-still-stage1-method',
    0x102c2f62: 'capture-still-stage1-part1',
    0x102c8f56: 'capture-still-stage1-part1-return',
    0x102c312a: 'capture-still-stage1-part2',
    0x102c8f5c: 'capture-still-stage1-part2-return',
    0x102c3212: 'capture-still-stage1-part3',
    0x102c8f62: 'capture-still-stage1-part3-return',
    0x102c32a6: 'capture-still-stage1-part4',
    0x102c8f68: 'capture-still-stage1-part4-return',
    0x102c3358: 'capture-still-stage1-part5',
    0x102c8f6e: 'capture-still-stage1-part5-return',
    0x102c34f2: 'capture-still-stage1-part6',
    0x102c8f74: 'capture-still-stage1-part6-return',
    0x102c8d72: 'capture-still-stage1-part7',
    0x102c8f7a: 'capture-still-stage1-part7-return',
    0x102c900c: 'capture-still-peer-wait',
    0x102c9010: 'capture-still-peer-wait-return',
    0x102c9020: 'capture-still-peer-ready',
    0x103ce51e: 'capture-still-peer-request',
    0x10328d36: 'capture-driver-image-request',
    0x10323b44: 'capture-driver-image-request-consumed',
    0x10321224: 'capture-driver-image-launch',
    0x10321284: 'capture-driver-image-launch-wait',
    0x10321288: 'capture-driver-image-launch-wait-return',
    0x10320e72: 'capture-driver-image-parameters-submitted',
    0x10395dae: 'capture-processing-phase10-entry',
    0x10395cf4: 'capture-processing-phase20-entry',
    0x10395da4: 'capture-processing-ready-notification',
    0x1022e802: 'capture-processing-ready-input-handler',
    0x10327caa: 'capture-input-metadata-task-routing',
    0x10326e86: 'capture-input-metadata-task',
    0x1031cb3a: 'capture-driver-stop-flags-stored',
    0x1024220a: 'capture-input-adapter-command',
    0x102421aa: 'capture-input-adapter-response',
    0x10394762: 'capture-processing-adapter-notification',
    0x1026ec26: 'capture-delegate-ready-notification-route',
    0x10394710: 'capture-processing-second-handshake-request',
    0x10395a70: 'capture-processing-first-handshake-request',
    0x10394d06: 'capture-processing-device-notification',
    0x10397260: 'capture-processing-stage18-entry',
    0x1024229c: 'capture-gpio-first-handshake',
    0x102422c4: 'capture-gpio-second-handshake',
    0x102422ec: 'capture-gpio-input-callback',
    0x10242124: 'capture-gpio-timer-callback',
    0x1026d16e: 'capture-sampling-delegate-notification',
    0x102e9482: 'capture-sampling-stage-handler',
    0x102e958a: 'capture-sampling-task',
    0x102e94fa: 'capture-sampling-second-step-producer',
    0x102eb93e: 'capture-sampling-stage5-wait',
    0x102eb778: 'capture-sampling-counter-callback',
    0x102e8630: 'capture-sampling-counter-configure',
    0x102e8684: 'capture-sampling-hardware-operation',
    0x102dc83c: 'capture-sampling-output-control',
    0x102dc808: 'capture-sampling-output-gate',
    0x10297710: 'capture-sampling-output-configure',
    0x102e9b08: 'capture-sampling-first-output-callback',
    0x102e9af6: 'capture-sampling-second-output-callback',
}
CAPTURE_CONTROLLER_POINTS = {
    0x080369d0: 'capture-controller-channel9-request',
    0x08036748: 'capture-controller-channel9-task',
    0x08036d38: 'capture-controller-channel9-command2',
    0x08036c60: 'capture-controller-channel9-result9',
    0x08035030: 'capture-controller-backend-configure',
    0x08035054: 'capture-controller-backend-configured',
    0x0803501c: 'capture-controller-backend-request',
    0x08034de0: 'capture-controller-backend-task',
    0x08035204: 'capture-controller-backend-start',
    0x080354b8: 'capture-controller-backend-hardware-start',
    0x08034d40: 'capture-controller-backend-phase-complete',
    0x08034dc0: 'capture-controller-backend-notification',
    0x080368ce: 'capture-controller-step-input-armed',
    0x0803661c: 'capture-controller-step-trigger',
    0x08034ff0: 'capture-controller-step-request',
    0x08036986: 'capture-controller-step-input-rearmed',
    0x08036830: 'capture-controller-step-input-callback',
}
CAPTURE_SLAVE_INIT_POINTS = {
    0x100535e0: 'capture-slave-compute-init-task',
    0x100535f8: 'capture-slave-compute-init-memory-ready',
    0x10054a2a: 'capture-slave-compute-init-program',
    0x10054a5a: 'capture-slave-compute-init-program-copy-return',
    0x100593a0: 'capture-slave-compute-init-configure',
    0x10054a80: 'capture-slave-compute-init-configure-return',
    0x10065c22: 'capture-slave-compute-init-memory-switch',
    0x100593f4: 'capture-slave-compute-control-one-entry',
    0x1005941c: 'capture-slave-compute-control-one-written',
    0x10059434: 'capture-slave-compute-status-check',
    0x1005944c: 'capture-slave-compute-state-request',
    0x1005947c: 'capture-slave-compute-flush-request',
}
CAPTURE_SLAVE_POINTS = {
    **CAPTURE_SLAVE_INIT_POINTS,
    0x10129faa: 'capture-slave-image-service',
    0x10129e12: 'capture-slave-still-request',
    0x10129e54: 'capture-slave-request-copy-return',
    0x10129e74: 'capture-slave-initial-reply-return',
    0x10129ece: 'capture-slave-context-copy-return',
    0x10129f28: 'capture-slave-parameters-copy-return',
    0x10129f88: 'capture-slave-stages-selected',
    0x10129f9a: 'capture-slave-work-submit',
    0x10129f9e: 'capture-slave-work-submit-return',
    0x1012bbfa: 'capture-slave-stage0-precondition',
    0x1012bc12: 'capture-slave-stage0-token-return',
    0x1012c45c: 'capture-slave-stage0-prepare',
    0x1012c51c: 'capture-slave-stage0-prepare-return',
    0x1012c520: 'capture-slave-stage0-transform',
    0x1012c5ea: 'capture-slave-stage0-transform-return',
    0x1012c630: 'capture-slave-stage0-statistics',
    0x1012c66c: 'capture-slave-stage0-statistics-return',
    0x1012bba6: 'capture-slave-stage0-token-wait',
    0x1012c334: 'capture-slave-stage0-finish',
    0x1012c3e6: 'capture-slave-stage1-prepare',
    0x1012eae4: 'capture-slave-stage1-input-wait',
    0x1012eb0a: 'capture-slave-stage1-input-wait-return',
    0x1012eb1a: 'capture-slave-stage1-input-ready',
    0x1012bc26: 'capture-slave-stage1-buffers',
    0x1012c2de: 'capture-slave-stage1-process',
    0x1011ef16: 'capture-slave-compute-entry',
    0x1011ef70: 'capture-slave-compute-first-return',
    0x1011efba: 'capture-slave-compute-second-return',
    0x10054a90: 'capture-slave-compute-driver',
    0x10054ab4: 'capture-slave-compute-initialized',
    0x10054aca: 'capture-slave-compute-submit-return',
    0x10054adc: 'capture-slave-compute-wait-return',
    0x10060b50: 'capture-slave-compute-channel-start',
}
IMAGE_WORK_POINTS = {
    0x103cc8e8: 'image-work-tracking-enqueue-mode2',
    0x103cc960: 'image-work-tracking-enqueue-mode1',
    0x102459fa: 'image-work-scheduler-submit',
    0x102457ac: 'image-work-first-stage',
    0x102456fc: 'image-work-later-stage',
    0x103d0c3a: 'image-work-completion',
    0x103ce236: 'image-still-work-completion',
}
CAPTURE_WORK_POINTS = {
    address: 'capture-' + label for address, label in IMAGE_WORK_POINTS.items()
}
CAPTURE_WORK_WAIT_POINTS = {
    0x102e6518: 'capture-work-token-wait',
    0x102e651c: 'capture-work-token-wait-return',
    0x10269e02: 'capture-work-result-wait',
    0x10269e06: 'capture-work-result-wait-return',
}
IMAGE_WORK_WAIT_POINTS = {
    0x10268c2a: 'image-work-service-wait',
    0x10268c2e: 'image-work-service-wait-return',
    0x10263a14: 'image-work-service-event-producer',
    0x10266476: 'image-work-dependent-wait',
    0x1026830e: 'image-work-second-service-wait',
    0x10268312: 'image-work-second-service-wait-return',
    0x10262e28: 'image-work-second-service-event-producer',
    0x1026981c: 'image-work-stage1-input-wait',
    0x10269820: 'image-work-stage1-input-wait-return',
    0x102698a0: 'image-work-stage1-result-wait',
    0x102698a4: 'image-work-stage1-result-wait-return',
    0x1026306c: 'image-work-stage1-input-event-producer',
    0x10262e40: 'image-work-bank1-transfer-callback',
    0x102664ac: 'image-work-final-dependent-wait',
    0x102664b0: 'image-work-final-dependent-wait-return',
    0x103699a4: 'image-device-bank0-interrupt',
    0x10369968: 'image-device-bank1-interrupt',
}
AFTER_PLAYBACK = {
    0x103f25ec: 'operation18-api',
    0x103ef386: 'operation18-task-request',
    0x103e7312: 'capture-mode-request',
    0x103e6e94: 'capture-state-transition',
    0x103237d4: 'capture-stop-driver-request',
    0x10323198: 'capture-driver-state-request',
    0x103237ec: 'capture-stop-driver-return',
    0x103e6c0a: 'operation18-completion-producer',
    0x1020e228: 'operation18-ui-dispatch',
    0x10323392: 'capture-stop-driver-branch',
    0x10322e3e: 'capture-stop-subsystem-request',
    0x103233d2: 'capture-stop-mode0-result',
    0x103233fc: 'capture-stop-mode1-result',
    0x1032340a: 'capture-stop-other-mode',
    0x10323430: 'capture-stop-other-mode-result',
    0x10322e64: 'capture-stop-queue-check',
    0x10322e84: 'capture-stop-parameter-result',
    0x10322eb0: 'capture-stop-prepare-result',
    0x10322ede: 'capture-stop-local-stop-result',
    0x10322f30: 'capture-stop-worker-result',
    0x103c5342: 'capture-stop-prepare-request',
    0x1023333e: 'capture-stop-local-stop',
    0x1023334a: 'capture-stop-local-lock-return',
    0x10233366: 'capture-stop-local-callback-return',
    0x10233370: 'capture-stop-local-join-return',
    0x102301b6: 'capture-stop-input-drain',
    0x1023c50a: 'capture-stop-input-mask-disable',
    0x1020c290: 'capture-stop-input-quiesce',
    0x1020c2c0: 'capture-stop-input-quiesce-return',
    0x1023c526: 'capture-stop-input-channel9-return',
    0x1023c52e: 'capture-stop-input-channel7-return',
    0x1023c53a: 'capture-stop-input-channel6-return',
    0x1023c54c: 'capture-stop-input-channel45-return',
    0x1023c558: 'capture-stop-input-channel3-return',
    0x1023c56c: 'capture-stop-input-channel1-return',
    0x10230212: 'capture-stop-input-disable-return',
    0x10233386: 'capture-stop-input-drain-return',
    0x10233394: 'capture-stop-worker-request',
    0x10398726: 'processing-stop-command',
    0x10321a4c: 'capture-driver-notification',
    0x10397260: 'processing-stop-worker',
    0x1026e204: 'processing-stop-delegate',
    0x1026e230: 'processing-stop-link-return',
    0x1026e242: 'processing-stop-sync-request',
    0x1026e246: 'processing-stop-sync-return',
    0x1026e24a: 'processing-stop-callback-return',
    0x1026e254: 'processing-stop-delegate-return',
    0x1039722c: 'processing-stop-finalize',
    0x102ea05a: 'processing-stop-event-request',
    0x102ea06e: 'processing-stop-event-wait',
    0x1026c91a: 'delegate-stop-command',
    0x1026c9a0: 'delegate-stop-wait',
    0x1026c9a4: 'delegate-stop-wait-return',
    0x1026c37c: 'delegate-wait-failure-notification',
    0x1026c9c4: 'delegate-stop-completion-notification',
    0x102e961c: 'link-stop-completion-first',
    0x102e9692: 'link-stop-completion-second',
    0x1026c174: 'delegate-diagnostic-configured',
    0x1026c220: 'delegate-diagnostic-stored-error',
    0x1026c25e: 'delegate-diagnostic-current-error',
    0x102d987c: 'local-stop-frame-wait',
    0x102d9880: 'local-stop-frame-wait-return',
    0x102d98c4: 'local-stop-control20-wait',
    0x102d98c8: 'local-stop-control20-wait-return',
    0x102d9902: 'local-stop-control10-wait',
    0x102d9906: 'local-stop-control10-wait-return',
    0x10296352: 'sampling-control-command',
    0x10296360: 'sampling-control-submit',
}
RETURN_POINTS = {
    0x1043898e: 'idle-shooting-request',
    0x1062e474: 'application-request-dispatch',
    0x106ddc1e: 'application-start-notification',
    0x10540770: 'shooting-render-entry',
    0x1053cfb8: 'shooting-application-entry',
    0x103f2540: 'operation14-api',
    0x103f258e: 'operation15-api',
    0x103f24e4: 'operation13-api',
    0x103f25bc: 'operation16-api',
    0x103f25d4: 'operation17-api',
    0x103f261a: 'operation19-api',
    0x103ef390: 'operation19-task-request',
    0x10247dea: 'operation14-ui-completion',
    0x10247e38: 'initialization-success-dispatch',
    0x1020dad2: 'initialization-main-state-forward',
    0x102470ae: 'initialization-state4-entry',
    0x102470d6: 'initialization-state4-parent-report',
    0x1020dc72: 'initialization-state4-ready-path',
    0x103e7312: 'capture-mode-request',
    0x10323198: 'capture-driver-state-request',
    0x10322886: 'capture-device-initialization',
    0x1023abaa: 'input-configuration-request',
    0x1023aed8: 'input-configuration-update',
    0x1020905a: 'input-geometry-setter',
    0x1036096a: 'public-request-entry-96a',
    0x1036096e: 'public-request-entry-96e',
    0x10360972: 'public-request-entry-972',
    0x1026c25e: 'delegate-diagnostic-current-error',
    0x103234b2: 'capture-device-initialization-return',
    0x10397c16: 'processing-start-command',
    0x10397526: 'processing-start-report',
    0x1026c6cc: 'delegate-start-command',
    0x1026c26a: 'sampling-start-request',
    0x102d7238: 'sampling-start-configuration',
    0x1026c704: 'delegate-start-wait4',
    0x1026c708: 'delegate-start-wait4-return',
    0x1026c71a: 'delegate-start-control-wait',
    0x1026c71e: 'delegate-start-control-wait-return',
    0x1026c37c: 'delegate-wait-failure-notification',
    0x10321a4c: 'capture-driver-notification',
    0x102d9780: 'sampling-run-request',
    0x102d93a2: 'sampling-run-sequence',
    0x102d949e: 'sampling-run-sync-wait',
    0x102d94a6: 'sampling-run-sync-wait-return',
    0x102d950c: 'sampling-run-delay1-wait',
    0x102d9510: 'sampling-run-delay1-wait-return',
    0x102d954c: 'sampling-run-delay2-wait',
    0x102d9550: 'sampling-run-delay2-wait-return',
    0x1026d534: 'resource-completion-notification',
    0x102d97fc: 'sampling-run-return',
    0x1026c732: 'delegate-sampling-run-return',
    0x1026c758: 'delegate-start-final-wait',
    0x1026c75c: 'delegate-start-final-join',
    0x1026c766: 'delegate-start-completion',
    0x1026d30e: 'delegate-start-final-confirmation',
    0x10394762: 'processing-notification',
    0x10394a12: 'processing-event-set',
    0x103949fc: 'processing-start-completion-event',
    0x10397562: 'processing-start-report-return',
    0x1039a006: 'processing-start-handler-continuation',
    0x1039a010: 'processing-start-parameters-return',
    0x10397064: 'processing-input-start-request',
    0x1039706a: 'processing-input-start-return',
    0x1039707a: 'processing-input-start-wait',
    0x1039707e: 'processing-input-start-wait-return',
    0x1039a018: 'processing-start-input-continuation',
    0x10395a88: 'processing-start-previous-input-wait',
    0x10395a8c: 'processing-start-previous-input-continuation',
    0x1039a01e: 'processing-start-output-continuation',
    0x10395158: 'processing-output-prepare',
    0x1039517c: 'processing-output-prepare-return',
    0x10395052: 'processing-output-parameters',
    0x1039508a: 'processing-output-parameters-return',
    0x1039a036: 'processing-output-parameters-continuation',
    0x1039a03c: 'processing-output-request-continuation',
    0x10394ec8: 'processing-output-timer-request',
    0x10394ef8: 'processing-output-timer-config-return',
    0x10394f08: 'processing-output-timer-start-return',
    0x1037160a: 'delay-timer-open',
    0x10371614: 'delay-timer-open-lock-return',
    0x10371704: 'delay-timer-configure',
    0x10371820: 'delay-timer-configure-return',
    0x10371a28: 'delay-timer-start',
    0x10371a38: 'delay-timer-start-return',
    0x10395116: 'processing-start-output-wait',
    0x1039511a: 'processing-start-output-wait-return',
    0x102422c2: 'input-handshake-start-submitted',
    0x102422ea: 'input-handshake-stop-submitted',
    0x1039a060: 'processing-start-handler-return',
    0x103c048a: 'resource-read-request',
    0x103c0664: 'resource-read-result',
}

CORE_WORKER_POINTS = {
    0x103b4e1e: 'reconfigure-processing-core-entry',
    0x103b4e60: 'reconfigure-processing-core-configure-begin',
    0x103b4e64: 'reconfigure-processing-core-configure-return',
    0x103b4ef4: 'reconfigure-processing-core-port-enable',
    0x103b4f10: 'reconfigure-processing-core-notify-start',
    0x103b4f26: 'reconfigure-processing-core-notification-wait',
    0x103b4f2a: 'reconfigure-processing-core-notification-return',
    0x103b4fbe: 'reconfigure-processing-core-module-poll',
    0x103b4fd0: 'reconfigure-processing-core-completion',
}

RECONFIGURE_POINTS = {
    **CORE_WORKER_POINTS,
    0x103ba6ea: 'reconfigure-remote-capture-submit',
    0x103ba164: 'reconfigure-release-phase-submit',
    0x103f36fa: 'reconfigure-operation59-api',
    0x103f19c0: 'reconfigure-operation59-task',
    0x1022827c: 'reconfigure-capture-callback-registration',
    0x103e7312: 'reconfigure-capture-mode-request',
    0x10528afe: 'reconfigure-release-settings-build',
    0x1052273e: 'reconfigure-release-settings-dispatch',
    0x1031dd62: 'reconfigure-driver-ready-bit1',
    0x10326700: 'reconfigure-driver-ready-bit2',
    0x10322666: 'reconfigure-backend-ready-notification',
    0x103ed7ac: 'reconfigure-global-release-ready',
    0x1038e7b8: 'reconfigure-backend-mode-request',
    0x1038dfec: 'reconfigure-backend-initialize',
    0x1038e092: 'reconfigure-backend-initialize-wait20',
    0x1038e2d6: 'reconfigure-backend-initialize-wait40',
    0x103191c6: 'reconfigure-driver-job-return',
    0x102290b0: 'reconfigure-readiness-state-compare',
    0x102295f6: 'reconfigure-readiness-notification',
    0x103eddb8: 'reconfigure-readiness-consumer',
    0x103edd08: 'reconfigure-operation13-state-update',
    0x10389b56: 'reconfigure-processing-address-bindings',
    0x10389b90: 'reconfigure-processing-port-configure',
    0x103b4b1e: 'reconfigure-processing-worker-configure-begin',
    0x103b4b26: 'reconfigure-processing-worker-configure-return',
    0x103b4b2e: 'reconfigure-processing-worker-controls-return',
    0x103b4b3e: 'reconfigure-processing-worker-notification-wait',
    0x103b4b42: 'reconfigure-processing-worker-notification-return',
    0x103bdb9e: 'reconfigure-processing-dma-configure',
    0x103bd03a: 'reconfigure-processing-controller-control4',
    0x103bded0: 'reconfigure-processing-module-configure',
    0x103bd07c: 'reconfigure-processing-module-start',
    0x102692ca: 'reconfigure-capture-display-surface',
    0x103e1d30: 'reconfigure-display-frame-selected',
    0x103e1dea: 'reconfigure-display-frame-submit',
    0x1046c3c2: 'reconfigure-display-format',
    0x1023c57a: 'reconfigure-mode1-output-complete',
    0x1023c5dc: 'reconfigure-mode1-output-return',
    0x10238d16: 'reconfigure-frame-count-check',
    0x10238d3e: 'reconfigure-frame-count-complete',
    0x1022e600: 'reconfigure-input-event8-check',
    0x10230368: 'reconfigure-finite-input-worker',
    0x102303e8: 'reconfigure-finite-input-notification',
    0x103204f2: 'reconfigure-driver-state5-producer',
    0x102301b6: 'reconfigure-input-drain',
    0x10230212: 'reconfigure-input-drain-return',
    0x1023c50a: 'reconfigure-input-disable',
    0x1020c290: 'reconfigure-raw-stop',
    0x1020c2c0: 'reconfigure-raw-stop-return',
    0x10233cf6: 'reconfigure-context-queue',
    0x103259cc: 'reconfigure-context-request',
    0x10326264: 'reconfigure-context-request-return',
}


def processing_worker_snapshot(remote, task):
    descriptor = int.from_bytes(remote.read(task + 0x3c, 4), 'little')
    result = dict(task=hex(task), descriptor=hex(descriptor),
                  state=remote.read(task + 0x40, 1)[0], event_object=hex(task + 0x2c))
    if 0xb1800000 <= descriptor < 0xb5efffe8:
        nodes = int.from_bytes(remote.read(descriptor, 4), 'little')
        count = remote.read(descriptor + 4, 1)[0]
        if count <= 64 and 0xb1800000 <= nodes < 0xb5effc00:
            data = remote.read(nodes, count * 16)
            result['nodes'] = [dict(index=index, tags=list(data[index * 16:index * 16 + 8]),
                word_8=hex(struct.unpack_from('<I', data, index * 16 + 8)[0]),
                word_c=hex(struct.unpack_from('<I', data, index * 16 + 12)[0]))
                for index in range(count)]
            for node in result['nodes']:
                parameters = int(node['word_c'], 0)
                if node['tags'][0] == 10 and 0xb1800000 <= parameters <= 0xb5efff60:
                    node['parameters'] = {hex(index * 4): hex(value) for index, value in enumerate(
                        struct.unpack('<40I', remote.read(parameters, 160)))}
    return result


def task_wait_snapshot(remote, task, slave=False):
    handle = int.from_bytes(remote.read(task, 4), 'little')
    kernel_id = handle & 0xffff
    result = dict(object=hex(task), handle=hex(handle), kernel_id=hex(kernel_id))
    if not 0 < kernel_id < 512:
        return result
    if slave:
        # 0x1003445c..70 allocates the pool; 0x10034518..60 assigns IDs from 1.
        pool = int.from_bytes(remote.read(0xc10167e8, 4), 'little')
        if not 0xc1000000 <= pool <= 0xc81e5000:
            return result
        tcb = pool + (kernel_id - 1) * 0xd8
    else:
        tcb = 0xb2c32f30 + kernel_id * 0xd8
    fields = struct.unpack('<48I', remote.read(tcb, 192))
    if fields[2] & 0xffff != kernel_id:
        return result
    # Original scheduler 0x10107040/0x1010709c stores/restores SP at +0xbc.
    # +0x40 is the syscall wait stack; +0x44 holds a wait argument.
    stack = fields[47]
    result.update(tcb=hex(tcb), flags=hex(fields[2]), entry=hex(fields[5]),
                  saved_sp=hex(stack), syscall_sp=hex(fields[16]),
                  wait_argument=hex(fields[17]), stack_code_candidates=[])
    if ((0xc1000000 <= stack <= 0xc81ffc00) if slave else
            (0xb5000000 <= stack <= 0xb5effc00)):
        values = struct.unpack('<256I', remote.read(stack, 1024))
        if slave:
            result['saved_frame_words'] = [hex(value) for value in values[:96]]
        result['stack_code_candidates'] = [dict(offset=hex(index * 4), value=hex(value))
            for index, value in enumerate(values) if 0x10020000 <= value < 0x107a0000]
    return result


def image_work_snapshot(remote, still=False):
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    result = []
    for address in ((0xb238e694,) if still else (0xb238e774, 0xb238e794, 0xb238e7b4)):
        node, count = word(address), word(address + 8)
        row = dict(address=hex(address), count=count, jobs=[])
        for unused in range(min(count, 8)):
            if not 0xb2c00000 <= node <= 0xb5effff4:
                break
            request = word(node + 8)
            if 0xb2c00000 <= request <= 0xb5effffc:
                parameters = word(request)
                if 0xb2c00000 <= parameters <= (0xb5efb42b if still else 0xb5efc1cf):
                    job = dict(request=hex(request), parameters=hex(parameters),
                        owner=hex(word(parameters + 0xc)))
                    if still:
                        job.update(queue_flags=hex(word(parameters + 0x74)),
                                   control_flags=remote.read(parameters + 0x4bd4, 1)[0])
                    else:
                        # 0x103d0c3a selects/removes tracking queues with these flags.
                        job.update(queue_flags=hex(word(parameters + 0x6c)),
                                   busy=remote.read(parameters + 0x3e30, 1)[0])
                    owner = word(parameters + 0xc)
                    if not still and unused < 4 and 0xb2c00000 <= owner <= 0xb5effd40:
                        data = remote.read(owner, 0x2c0)
                        job['owner_output_words'] = {hex(offset): hex(struct.unpack_from('<I', data, offset)[0])
                                                     for offset in range(0x60, 0x84, 4)}
                        if unused == 0:
                            descriptors = []
                            for offset in (0x6c, 0x74, 0x78, 0x7c, 0x80):
                                pointer = struct.unpack_from('<I', data, offset)[0]
                                size = 0x80 if offset == 0x74 else 0x60
                                if 0xb2c00000 <= pointer <= 0xb5f00000 - size:
                                    values = struct.unpack('<' + str(size // 4) + 'I', remote.read(pointer, size))
                                    descriptors.append(dict(owner_offset=hex(offset), address=hex(pointer),
                                        fields={hex(at * 4): hex(value) for at, value in enumerate(values)}))
                            job['owner_output_descriptors'] = descriptors
                        headers = []
                        seen = set()
                        for offset in range(0x10, len(data), 4):
                            pointer = struct.unpack_from('<I', data, offset)[0]
                            if pointer in seen or not 0xb2c00000 <= pointer <= 0xb5efffc8:
                                continue
                            seen.add(pointer)
                            header = remote.read(pointer, 0x38)
                            shapes = [struct.unpack_from('<HH', header, at) for at in (0x1e, 0x28)]
                            if not any(shape in ((30, 20), (60, 40), (1380, 918), (1024, 682))
                                       for shape in shapes):
                                continue
                            headers.append(dict(owner_offset=hex(offset), address=hex(pointer),
                                fields={hex(at): hex(struct.unpack_from('<I', header, at)[0])
                                        for at in range(0, 0x38, 4)}))
                        job['owner_image_headers'] = headers
                    if request <= 0xb5effd30:
                        data = remote.read(request + 0x8c, 88)
                        states = list(data[::8])
                        indices = [struct.unpack_from('<I', data, index * 8 + 4)[0]
                                   for index in range(11)]
                        table = word(request + 4)
                        job.update(stage_table=hex(table), completion=hex(word(request + 0x2c8)),
                                   stage_states=states, stage_indices=indices, active_stages=[])
                        if 0xb1800000 <= table <= 0xb5effd6c:
                            entries = struct.unpack('<165I', remote.read(table, 660))
                            for index, state in enumerate(states):
                                column = indices[index]
                                if state == 3 or column >= 15:
                                    continue
                                descriptor = entries[index * 15 + column]
                                if 0xb1800000 <= descriptor <= 0xb5efffd8:
                                    active = dict(stage=index, state=state,
                                        column=column, descriptor=hex(descriptor),
                                        fields=[hex(value) for value in struct.unpack(
                                            '<10I', remote.read(descriptor, 40))])
                                    methods = int(active['fields'][5], 16)
                                    if still and 0xb1800000 <= methods <= 0xb5efff10:
                                        values = struct.unpack('<60I', remote.read(methods, 240))
                                        active['methods'] = [dict(index=i, fields=[hex(v) for v in values[i*3:i*3+3]])
                                            for i in range(20) if any(values[i*3:i*3+3])]
                                    job['active_stages'].append(active)
                    row['jobs'].append(job)
            node = word(node + 4)
        result.append(row)
    return result


def display_delivery_snapshot(read):
    def word(address):
        return int.from_bytes(read(address, 4), 'little')
    pointer = word(0xb1808580)
    result = dict(mode=read(0xb180854c, 1)[0], state=read(0xb1d178dc, 1)[0],
                  submit_state=read(0xb1d17ded, 1)[0], context=hex(pointer))
    if 0xb1800000 <= pointer <= 0xb5eff628:
        result.update(accepting=word(pointer + 0x240), deferred=read(pointer + 0x51c, 1)[0],
                      deferred_background=hex(word(pointer + 0x614)))
    return result


def image_service_snapshot(remote):
    def words(address, count):
        return struct.unpack('<' + str(count) + 'I', remote.read(address, count * 4))
    result_routes = words(0xb1801d78, 48)
    return dict(library_modes=list(remote.read(0xb1801ecc, 2)),
        transfer_result_callbacks=[hex(value) for value in words(0xb1cf0f40, 8)],
        transfer_result_routes=[dict(status=hex(0x2010001c if index < 16 else 0x20100020),
            mask=hex(mask), payload=hex(payload)) for index, (mask, payload) in enumerate(
                zip(result_routes[::2], result_routes[1::2]))],
        transfer_result_units=[dict(index=index, registers={hex(offset * 4): hex(value)
            for offset, value in enumerate(words(base, 6))})
            for index, base in ((49, 0x20100940), (54, 0x201009e0), (55, 0x20100ba0))],
        library_callbacks=[hex(value) for value in words(0xb1801ed4, 2)],
        service_fields={hex(index * 4): hex(value)
                        for index, value in enumerate(words(0xb18095c4, 24))},
        banks=[dict(base=hex(base), registers={hex(index * 4): hex(value)
                    for index, value in enumerate(words(base, 256))})
               for base in (0x20380000, 0x203c0000)])


def input_tail_parameter_snapshot(remote, pointer):
    """Read the two original tail-worker conditions without changing them."""
    result = dict(address=hex(pointer))
    if not 0xb2c00000 <= pointer <= 0xb5effb08:
        return result
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    nested = word(pointer + 0x4f4)
    result.update(parameter_2b4=hex(word(pointer + 0x2b4)), nested=hex(nested))
    if 0xb2c00000 <= nested <= 0xb5efd7b4:
        result.update(nested_2844=hex(word(nested + 0x2844)),
                      nested_2848=hex(word(nested + 0x2848)))
    return result


def capture_request_variant_slots_snapshot(remote):
    result = []
    for address, offsets in ((0xb23f6c30, (8, 0x34, 0x38)),
                              (0xb23f6ca0, (8,)), (0xb23f6ce8, (8, 0x24))):
        row = dict(address=hex(address), state=remote.read(address + 5, 1)[0],
            words={hex(offset): hex(int.from_bytes(remote.read(address + offset, 4), 'little'))
                   for offset in offsets})
        if address == 0xb23f6c30:
            row['field_42'] = remote.read(address + 0x42, 1)[0]
        result.append(row)
    return result


def still_input_snapshot(remote, pointer):
    """Read the selected full-input context and its original dispatch conditions."""
    result = input_tail_parameter_snapshot(remote, pointer)
    if not 0xb2c00000 <= pointer <= 0xb5effb08:
        return result
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    result['fields'] = {hex(offset): hex(word(pointer + offset)) for offset in
                        (0, 8, 0x2b0, 0x2b4, 0x2bc, 0x2c0, 0x30c, 0x314, 0x43c)}
    nested = int(result['nested'], 16)
    if 0xb2c00000 <= nested <= 0xb5efe1c4:
        result['nested_fields'] = {hex(offset): hex(int.from_bytes(
            remote.read(nested + offset, size), 'little')) for offset, size in
            ((0x98, 1), (0x9c, 4), (0xc0, 1), (0xc4, 4), (0xc8, 1),
             (0x54e, 1), (0x1df0, 4), (0x1e38, 4))}
    return result


def still_queue_snapshot(remote):
    return [dict(address=hex(address), words=[hex(value) for value in struct.unpack(
        '<8I', remote.read(address, 32))]) for address in
        (0xb238e694, 0xb238e6b4, 0xb238e754)]


def input_context_snapshot(remote):
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    result = []
    # These four queues are traversed as contexts by 0x102300b0.
    for address in (0xb25eeba4, 0xb25eebc4, 0xb25eebe4, 0xb25eec04):
        node, count = word(address), word(address + 8)
        row = dict(address=hex(address), count=count, head=hex(node), contexts=[])
        for unused in range(min(count, 8)):
            if not 0xb2c00000 <= node <= 0xb5effff4:
                break
            context = word(node + 8)
            if 0xb2c00000 <= context <= 0xb5effeaf:
                item = dict(address=hex(context),
                    consumers=remote.read(context + 0xc, 1)[0],
                    parameters=hex(word(context + 0x144)),
                    pending=hex(word(context + 0x14c)))
                if unused == 0:
                    item['output_headers'] = []
                    for offset in (0x68, 0x6c, 0x70, 0x74):
                        pointer = word(context + offset)
                        size = {0x68: 0x38, 0x6c: 0x60, 0x70: 0x34, 0x74: 0x80}[offset]
                        if 0xb2c00000 <= pointer <= 0xb5f00000 - size:
                            values = struct.unpack('<' + str(size // 4) + 'I', remote.read(pointer, size))
                            item['output_headers'].append(dict(offset=hex(offset), address=hex(pointer),
                                words=[hex(value) for value in values]))
                row['contexts'].append(item)
            node = word(node + 4)
        result.append(row)
    return result


def primary_input_snapshot(remote):
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    result = dict(geometry={hex(0x20069500 + offset): hex(word(0x20069500 + offset))
                           for offset in range(0, 0x14, 4)},
        dma={hex(offset): hex(word(0x20069800 + offset))
             for offset in (8, 0x14, 0x18, 0x3c, 0x40, 0x44, 0x48, 0x50, 0x60)},
        second_dma={hex(offset): hex(word(0x20069900 + offset))
                    for offset in (8, 0x50, 0x54, 0x58, 0x5c, 0x60, 0x64, 0x68, 0x6c)},
        buffers=[])
    result['address_remap'] = []
    for base in (0x201350b0, 0x2013d0b0):
        values = struct.unpack('<40I', remote.read(base, 0xa0))
        result['address_remap'].append(dict(base=hex(base), entries=[dict(slot=index,
            target_page=hex(values[index]), mask_page=hex(values[index + 8]),
            aperture_page=hex(values[index + 16]), word_60=hex(values[index + 24]),
            word_80=hex(values[index + 32])) for index in range(8)]))
    ttbr = (remote.read_register('TTBR0_S') if all(name in remote.register_numbers
            for name in ('TTBR0_S', 'TTBCR_S')) and
            remote.read_register('TTBCR_S') == 0 else None)
    if ttbr is not None:
        result['execution_sections'] = []
        for address in (0x10100000, 0x1020c334, 0x1038848a, 0x10542038, 0xb26b3924):
            descriptor = word((ttbr & 0xffffc000) + (address >> 20) * 4)
            row = dict(address=hex(address), descriptor=hex(descriptor))
            if descriptor & 3 == 2:
                row['physical_address'] = hex((descriptor & 0xfff00000) | (address & 0xfffff))
            result['execution_sections'].append(row)
    for name, register in (('input', 0x20069850), ('output0', 0x2006a450),
                           ('output1', 0x2006a550)):
        address = word(register)
        row = dict(name=name, address=hex(address))
        # Only inspect recovered ordinary storage, never an arbitrary MMIO
        # operand. A GDB-side read failure is evidence, not a guest completion.
        if 0x62700000 <= address <= 0xac1c4000:
            response = remote.command(f'm{address:x},1000')
            row['readable'] = not response.startswith('E')
            if row['readable']:
                data = bytes.fromhex(response)
                row['sample'] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                    unique_bytes=len(set(data)), minimum=min(data), maximum=max(data))
            if ttbr is not None:
                descriptor = word((ttbr & 0xffffc000) + (address >> 20) * 4)
                row['section_descriptor'] = hex(descriptor)
                if descriptor & 3 == 2:
                    row['physical_address'] = hex((descriptor & 0xfff00000) | (address & 0xfffff))
        result['buffers'].append(row)
    return result


def auxiliary_image_snapshot(remote):
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    def register(offset):
        response = remote.command(f'm{0x20201000 + offset:x},4')
        # Unsupported device words may be unassigned in the current profile.
        return None if response.startswith('E') else hex(int.from_bytes(bytes.fromhex(response), 'little'))
    current = word(0xb1809630)
    result = dict(task=task_wait_snapshot(remote, 0xb1d52be0), current=hex(current),
        runtime=hex(word(0xb1801ef8)),
        registers={hex(offset): register(offset) for offset in
            (0, 4, 0x14, 0x20, 0x2c, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x5c, 0x60,
             0xa0, 0xa4, 0xa8, 0xac, 0xb0, 0xb4, 0xb8, 0xbc, 0xc0, 0xc4, 0xc8, 0xcc,
             0x100, 0x104, 0x108, 0x10c, 0x110, 0x118, 0x11c, 0x120, 0x124,
             0x128, 0x12c, 0x130, 0x140, 0x160, 0x164, 0x168, 0x16c, 0x170,
             0x178, 0x188, 0x1a0)})
    translation = {name: remote.read_register(name) for name in remote.register_numbers
                   if name.startswith(('TTBR0', 'TTBR1', 'TTBCR'))}
    result['translation_registers'] = {name: hex(value) for name, value in translation.items()}
    if 'TTBR0_S' in translation and translation.get('TTBCR_S') == 0:
        descriptor = word((translation['TTBR0_S'] & 0xffffc000) + 0x202 * 4)
        result['section_descriptor'] = hex(descriptor)
        if descriptor & 3 == 2:
            result['physical_base'] = hex((descriptor & 0xfff00000) | 0x1000)
    # 0x1022e6b0 uses the subcontext at 0xb1887df0, not 0xb1887d70.
    handle = word(0xb1887e0c)
    node, count = word(0xb1d607e8), word(0xb1d607f0)
    dispatch = dict(handle_address='0xb1887e0c', handle=hex(handle),
                    registry_count=count, scanned=0, matches=[])
    for index in range(min(count, 64)):
        if not 0xb1800000 <= node <= 0xb5effff3:
            break
        entry = word(node + 8)
        if 0xb1800000 <= entry <= 0xb5efffdf and word(entry + 4) == handle:
            dispatch['matches'].append(dict(index=index, record=hex(entry),
                route=remote.read(entry, 1)[0], callback=hex(word(entry + 0x1c))))
        dispatch['scanned'] += 1
        node = word(node + 4)
    result['input_result_dispatch'] = dispatch
    if 0xb1800000 <= current <= 0xb5efff27:
        result['configuration'] = {hex(offset): hex(word(current + offset)) for offset in
            (0, 4, 0xc, 0x10, 0x14, 0x18, 0x20, 0x24, 0x28,
             0x2c, 0x3c, 0x4c, 0x5c, 0x6c, 0x70, 0x74, 0x78,
             0x80, 0x88, 0x8c, 0x90, 0x94, 0xa4, 0xac, 0xb4, 0xc0, 0xcc, 0xd0)}
    return result


def sd_trace_snapshot(machine):
    if not getattr(machine.args, 'trace_sd_host', False):
        return None
    events, counts = [], {}
    pattern = re.compile(r'(sdhci_send_command|sdhci_adma_loop|sdhci_adma|sdhci_access|sdcard_write_block) (.*)')
    for line in (machine.work / 'qemu.log').open(encoding='utf-8', errors='replace'):
        match = pattern.search(line)
        if not match:
            continue
        event, detail = match.groups()
        counts[event] = counts.get(event, 0) + 1
        if event == 'sdhci_access':
            access = re.fullmatch(r'wr(8|16|32): addr\[0x([0-9a-f]+)\] <- 0x([0-9a-f]+) \(\d+\)', detail)
            if not access or int(access[2], 16) not in (0, 4, 8, 0xc, 0xe, 0x28, 0x58, 0x5c):
                continue
            item = dict(event=event, bits=int(access[1]), offset=hex(int(access[2], 16)),
                        value=hex(int(access[3], 16)))
        else:
            item = dict(event=event, detail=detail)
        counts['selected'] = counts.get('selected', 0) + 1
        if len(events) < 256:
            events.append(item)
    return dict(counts=counts, events=events, event_limit=256,
        truncated=counts.get('selected', 0) > len(events),
        scope='Ordered command, DMA and control metadata only; data-port contents are excluded')


def peer_input_snapshot(remote, resume_thread=1):
    result = dict(thread=3, controls={}, banks=[])
    remote.select_thread(3)
    try:
        def word(address):
            return int.from_bytes(remote.read(address, 4), 'little')
        result['controls'] = {hex(offset): hex(word(0x20068000 + offset))
                              for offset in (0, 4, 8, 0xc, 0x10, 0x14, 0x18)}
        result['banks'] = [dict(bank=bank, mask=hex(word(0x20068200 + bank * 32)),
                               status=hex(word(0x20068210 + bank * 32))) for bank in range(8)]
        result['geometry'] = [hex(value) for value in
                              struct.unpack('<5I', remote.read(0x20069500, 20))]
        result['image_banks'] = [dict(base=hex(base),
            controls=[hex(value) for value in struct.unpack('<5I', remote.read(base, 20))])
            for base in (0x20380000, 0x203c0000)]
        context = word(0xc144f584 + 3 * 4)
        result['image_service'] = dict(context=hex(context))
        if 0xc1000000 <= context <= 0xc81f39c0:
            result['image_service']['tail'] = [hex(value) for value in struct.unpack(
                '<16I', remote.read(context + 0xc600, 64))]
        compute = dict(service_words=[hex(value) for value in struct.unpack(
            '<4I', remote.read(0xc1007168, 16))],
            request_words=[hex(value) for value in struct.unpack(
                '<3I', remote.read(0xc1690a80, 12))],
            parameter_words={hex(offset): hex(word(0xc1690a8c + offset)) for offset in
                (0, 4, 8, 0xc, 0x4c, 0x50, *range(0x484, 0x5ac, 4))},
            output_words=[hex(value) for value in struct.unpack(
                '<3I', remote.read(0xc500c4e0, 12))])
        compute['core_words'] = {hex(offset): hex(word(0x24060000 + offset))
                                 for offset in range(0, 0x40, 4)}
        compute['clock_words'] = {hex(offset): hex(word(0x04281000 + offset))
                                  for offset in (0x20, 0x28, 0x30, 0x34, 0x58, 0x5c)}
        compute['gate_125_word'] = hex(word(0x04280084))
        engine = word(0xc1006408)
        compute['engine'] = hex(engine)
        if 0xc1000000 <= engine <= 0xc81fffec:
            data = remote.read(engine, 20)
            compute['engine_words'] = [hex(value) for value in struct.unpack('<5I', data)]
            bank, channel = data[4], data[5]
            if bank < 2 and channel < 8:
                base = (0x04250000, 0x24061000)[bank]
                registers = base + 0x100 + channel * 0x80
                compute.update(bank=bank, channel=channel, registers=hex(registers),
                    busy_channels=hex(word(base + 0x900)),
                    request_irq_head=hex(word(base + 0x80)),
                    result_irq_head=hex(word(base + 0x84)),
                    channel_words=[hex(value) for value in struct.unpack(
                        '<32I', remote.read(registers, 128))])
        result['compute'] = compute
        compute['memory_channels'] = [dict(channel=channel, words=[hex(value) for value in
            struct.unpack('<11I', remote.read(0x04251010 + channel * 0x30, 44))])
            for channel in range(4)]
        compute['tasks'] = {name: task_wait_snapshot(remote, task, slave=True)
            for name, task in (('initialization', 0xc167b798),
                               ('stage0', 0xc1008d88), ('stage1', 0xc1008dbc))}
        compute['initialization_object_words'] = [hex(value) for value in struct.unpack(
            '<8I', remote.read(0xc167b798, 32))]
        queue = 0xc16a58a8
        node, count = word(queue), word(queue + 8)
        result['still_work'] = dict(queue=hex(queue), count=count, jobs=[])
        for unused in range(min(count, 4)):
            if not 0xc1000000 <= node <= 0xc81ffff4:
                break
            request = word(node + 8)
            if not 0xc1000000 <= request <= 0xc81ffd30:
                break
            parameters, table = word(request), word(request + 4)
            data = remote.read(request + 0x8c, 88)
            states = list(data[::8])
            indices = [struct.unpack_from('<I', data, index * 8 + 4)[0] for index in range(11)]
            job = dict(request=hex(request), parameters=hex(parameters), table=hex(table),
                       completion=hex(word(request + 0x2c8)), stage_states=states,
                       stage_indices=indices, active_stages=[])
            if 0xc1000000 <= table <= 0xc81ffd6c:
                entries = struct.unpack('<165I', remote.read(table, 660))
                for stage, state in enumerate(states):
                    column = indices[stage]
                    if state == 3 or column >= 15:
                        continue
                    descriptor = entries[stage * 15 + column]
                    if 0xc1000000 <= descriptor <= 0xc81fffd8:
                        active = dict(stage=stage, state=state, column=column,
                            descriptor=hex(descriptor), fields=[hex(value) for value in
                                struct.unpack('<10I', remote.read(descriptor, 40))])
                        methods = int(active['fields'][5], 16)
                        if 0xc1000000 <= methods <= 0xc81fff10:
                            values = struct.unpack('<60I', remote.read(methods, 240))
                            active['methods'] = [dict(index=i, fields=[hex(v) for v in values[i*3:i*3+3]])
                                for i in range(20) if any(values[i*3:i*3+3])]
                        job['active_stages'].append(active)
            result['still_work']['jobs'].append(job)
            node = word(node + 4)
    except ValueError as error:
        result['read_error'] = str(error)
    finally:
        remote.select_thread(resume_thread)
    return result


def master_compute_snapshot(remote):
    remote.select_thread(1)
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    return dict(service_words=[hex(value) for value in struct.unpack(
                    '<4I', remote.read(0xb1808d14, 16))],
                channel_owners=[hex(word(0x24061100 + index * 0x80)) for index in range(8)],
                busy_bitmap=hex(word(0x24061900)),
                request_ack_head=hex(word(0x24061080)),
                result_head=hex(word(0x24061084)),
                program_sha256=hashlib.sha256(remote.read(0x50200000, 0x27800)).hexdigest())


def card_admission_snapshot(remote):
    # C 1.70 scalar descriptors selected by the original 0x10101f52 lookup.
    parameters = (
        (0x127a, 'slot_empty_release_lock', 0x118ff2f4, 0xb258700c),
        (0x2f00, 'card_slot1', 0x11905534, 0xb258bfa8),
        (0x2f01, 'card_slot2', 0x11905544, 0xb258bfac),
        (0x2f0e, 'card_information_valid', 0x11905614, 0xb258c0d0),
        (0x1b04, 'image_save_media', 0x11903654, 0xb255211c),
        (0x2600, 'usb_connection', 0x11904eb4, 0xb25526ac),
        (0x3600, 'derived_parameter_3600', 0x11905974, 0xb257533c),
        (0x1916, 'derived_parameter_1916', 0x11903484, 0xb2551f94),
    )
    result = {}
    for identifier, name, descriptor, address in parameters:
        kind, size, actual, _ = struct.unpack('<4I', remote.read(descriptor, 16))
        require(kind in (0, 7) and size == 4 and actual == address,
                'Original card admission scalar descriptor differs')
        result[name] = dict(identifier=hex(identifier), descriptor=hex(descriptor),
                            address=hex(address), value=int.from_bytes(remote.read(address, 4), 'little'))
    return result


def engine_release_gpio_snapshot(remote, resume_thread=1):
    """Observe the main engine's independent release input descriptors."""
    remote.select_thread(1)
    try:
        def word(address):
            return int.from_bytes(remote.read(address, 4), 'little')
        contacts = []
        for name, resource in (('half', 0x58), ('full', 0x59)):
            descriptor = 0xb180249c + resource * 56
            contacts.append(dict(contact=name, resource=resource, descriptor=hex(descriptor),
                intid=word(descriptor + 0x28),
                edge_mode=remote.read(descriptor + 0x34, 1)[0],
                callback=hex(word(descriptor + 0x30))))
        return dict(gpio=hex(word(0x04282014)),
            mask=hex(word(0x0426f000)), pending=hex(word(0x0426f008)),
            polarity=hex(word(0x0426f014)), contacts=contacts,
            state=[hex(value) for value in struct.unpack('<13I', remote.read(0xb18698cc, 52))])
    finally:
        remote.select_thread(resume_thread)


def controller_release_irq_snapshot(remote, resume_thread=1):
    """Read native body-contact GPIO/EXTI bindings without acknowledging IRQs."""
    remote.select_thread(5)
    try:
        def word(address):
            return int.from_bytes(remote.read(address, 4), 'little')
        exti = [word(0x40013c00 + offset) for offset in range(0, 24, 4)]
        routes = [word(0x40013808 + index * 4) for index in range(4)]
        mode, levels = word(0x40021800), word(0x40021810)
        vtor = word(0xe000ed08)
        contacts = []
        for name, pin, index, irq, callback in (
                ('half', 1, 9, 7, 0x2000f384), ('full', 13, 11, 40, 0x2000f468)):
            descriptor = word(0x200184c8 + index * 4)
            row = dict(contact=name, pin=pin, gpio_mode=(mode >> (pin * 2)) & 3,
                gpio_level=(levels >> pin) & 1,
                exti_port=(routes[pin // 4] >> ((pin % 4) * 4)) & 15,
                interrupt_enabled=bool(exti[0] & 1 << pin),
                rising_enabled=bool(exti[2] & 1 << pin),
                falling_enabled=bool(exti[3] & 1 << pin), pending=bool(exti[5] & 1 << pin),
                callback_slot=hex(callback), callback=hex(word(callback)),
                descriptor=hex(descriptor), irq=irq,
                nvic_enabled=bool(word(0xe000e100 + (irq // 32) * 4) & 1 << (irq % 32)))
            if 0x20000000 <= descriptor <= 0x2003fff0:
                row['descriptor_words'] = [hex(value) for value in struct.unpack(
                    '<4I', remote.read(descriptor, 16))]
            if 0x20000000 <= vtor <= 0x2003ff00 and vtor % 128 == 0:
                row['vector'] = hex(word(vtor + (16 + irq) * 4))
            contacts.append(row)
        return dict(vtor=hex(vtor), exti_words=[hex(value) for value in exti],
                    route_words=[hex(value) for value in routes], contacts=contacts)
    finally:
        remote.select_thread(resume_thread)


def snapshot(remote):
    remote.select_thread(1)
    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')
    mode = remote.read(0xb1818d28, 2)
    state = remote.read(0xb1821b18, 1)[0]
    handler_object = word(0xb202f728 + state * 4)
    size, pointer = struct.unpack('<II', remote.read(0xb187556c, 8))
    codes = None
    if size == 0x118 and pointer:
        count = word(pointer + 0x110)
        if count <= 68:
            codes = [hex(x) for x in struct.unpack('<' + 'I' * count,
                                                 remote.read(pointer, count * 4))]
    notifications = remote.read(0x1094559c, 44 * 8)
    manager = remote.read(0xb1811e40, 28)
    engines = {}
    for name, thread in (('master', 1), ('slave', 3)):
        remote.select_thread(thread)
        engines[name] = dict(
            input_format=hex(word(0x20068500)),
            input_geometry=[hex(word(0x20069500 + i * 4)) for i in range(3)])
    remote.select_thread(5)
    controller_capture = dict(header=list(remote.read(0x2001359c, 6)),
        release_input_irq=controller_release_irq_snapshot(remote, 5),
        words={hex(offset): hex(word(0x2001359c + offset)) for offset in range(0x14, 0x3c, 4)},
        backend_header=list(remote.read(0x2001756c, 24)),
        backend_words={hex(offset): hex(word(0x2001756c + offset)) for offset in range(0x18, 0x2c, 4)},
        backend_request=list(remote.read(0x2000e8c0, 6)),
        backend_timer_bases=[hex(word(0x20018718 + offset)) for offset in (0x58, 0xd0)],
        faults=[hex(word(0xe000ed28)), hex(word(0xe000ed2c))])
    lens_descriptor = word(0x2000EE10 + 96 * 4)
    lens_detection = dict(controller_g0_level=word(0x40021810) & 1,
        descriptor=hex(lens_descriptor),
        debounced_samples=list(remote.read(0x2000E92C, 2)),
        reported_connection=remote.read(0x2000E778, 1)[0])
    if 0x20000000 <= lens_descriptor <= 0x2001FFF0:
        lens_detection['descriptor_fields'] = [hex(value) for value in
            struct.unpack('<4I', remote.read(lens_descriptor, 16))]
    remote.select_thread(1)
    lens_detection['master_connection'] = remote.read(0xB188A27A, 1)[0]
    engine_release_gpio = engine_release_gpio_snapshot(remote)
    resources = {}
    for index in (11, 71, 80):
        row = 0xb185eb70 + index * 28
        callbacks = 0xb20a3288 + index * 48
        resources[str(index)] = dict(buffer=hex(word(row + 8)), length=word(row + 12),
            region=word(row + 20), notification_mask=hex(word(callbacks + 40)),
            subscriber_count=int.from_bytes(remote.read(callbacks + 44, 2), 'little'))
    readiness = dict(state=remote.read(0xb18697e0, 1)[0],
        driver_flags=hex(word(0xb1868b68)),
        driver_subscriber=hex(word(0xb1868b38)),
        global_subscriber=hex(word(0xb18695ac)),
        backend_state=list(remote.read(0xb21e26b5, 2)),
        callback=hex(word(0xb18697e4)), enabled_notifications=hex(word(0xb18697e8)),
        operation13_pending=word(0xb23f6a7c), operation13_callback=hex(word(0xb23f7018)),
        bitmaps=[])
    for address in (0xb1869818, 0xb1869820):
        capacity, pointer = struct.unpack('<2I', remote.read(address, 8))
        row = dict(descriptor=hex(address), capacity=capacity, pointer=hex(pointer))
        if 0 < capacity <= 128 and 0xb1800000 <= pointer <= 0xb5effff0:
            values = struct.unpack('<' + 'I' * ((capacity + 31) // 32),
                                   remote.read(pointer, ((capacity + 31) // 32) * 4))
            row['set_bits'] = [index for index in range(capacity)
                               if values[index // 32] & 1 << (index % 32)]
        readiness['bitmaps'].append(row)
    delay_channels = []
    for channel in range(12):
        base = 0x2c010100 + channel * 0x100
        divider, terminal, count = struct.unpack('<3I', remote.read(base + 0x1004, 12))
        limit = None
        if channel < 5:
            enable, target, observed = struct.unpack('<3I', remote.read(base + 0x1038, 12))
            limit = dict(enabled=enable, target=target, observed=observed)
        capture = None
        if channel in (5, 6):
            values = struct.unpack('<5I', remote.read(base + 0x1010, 20))
            capture = dict(enabled=values[0], latches=[hex(x) for x in values[1:3]],
                           routing_enabled=values[3], source=values[4],
                           alternate_mode=hex(word(base + 8)))
        delay_channels.append(dict(channel=channel, events=hex(word(base)),
            pending=hex(word(base + 16)), divider=divider,
            terminal=hex(terminal), count=hex(count), repetition_limit=limit, capture=capture))
    cores = []
    for thread in (1, 2, 3, 4):
        remote.select_thread(thread)
        registers = remote.regs()
        cores.append(dict(thread=thread, pc=hex(remote.get(registers, 'pc')),
            faults={name: hex(remote.read_register(name)) for name in
                    ('DFAR_S', 'IFAR_S', 'DFSR_S', 'IFSR_S')}))
    remote.select_thread(1)
    geometry = list(struct.unpack('<13I', remote.read(0x20069500, 13 * 4)))
    input_channels = []
    for base, count in ((0x20069800, 4), (0x2006a400, 10), (0x2006b400, 10)):
        for channel in range(count):
            address = base + channel * 0x100
            values = {}

            def capture_words(offset, words=1):
                data = remote.read(address + offset, words * 4)
                for index, (value,) in enumerate(struct.iter_unpack('<I', data)):
                    values[hex(offset + index * 4)] = hex(value)

            if count == 4:
                capture_words(8)
                capture_words(0x50, 8)
                if not channel & 1:
                    capture_words(0x14, 2)
                    capture_words(0x3c, 5)
                if channel == 2:
                    capture_words(0x24)
                if channel >= 2:
                    capture_words(0x80)
            else:
                capture_words(0x14, 2)
                capture_words(0x24)
                capture_words(0x3c, 6)
                capture_words(0x60)
                capture_words(0x74)
                capture_words(0x80)
                if channel in (2, 3, 4, 9):
                    capture_words(0x54, 3)
                    capture_words(0x64, 3)
            if any(int(value, 16) for value in values.values()):
                input_channels.append(dict(base=hex(address), fields=values))
    driver_queue = struct.unpack('<5I', remote.read(0xb23ede14, 20))
    driver_pending = None
    base, stride, capacity, count, head = driver_queue
    if base == 0xb23ede2c and stride == 0x5c and capacity == 60 and count <= capacity and head < capacity:
        data = remote.read(base, stride * capacity)
        driver_pending = [hex(struct.unpack_from('<I', data, ((head + index) % capacity) * stride)[0])
                          for index in range(count)]
    completed_heads = []
    for index in range(4):
        node = word(0xb26b3924 + index * 32)
        item = dict(node=hex(node))
        if 0xb2c00000 <= node < 0xb5effff4:
            value = word(node + 8)
            item['value'] = hex(value)
            if 0xb2c00000 <= value < 0xb5effeb0:
                item['raw_fields'] = {hex(offset): hex(word(value + offset))
                                      for offset in (0x144, 0x14c)}
        completed_heads.append(item)
    output_config = remote.read(0xb26b44cc, 0x44)
    output_registers = {}
    if output_config[0] < 10:
        for offset in range(0, 0x348, 0x28):
            address = word(0xb18069d4 + output_config[0] * 4 + offset)
            if 0x20068000 <= address < 0x20070000:
                item = dict(address=hex(address))
                if (address & 0xff) in (0x14, 0x18, 0x24, 0x3c, 0x40, 0x44,
                                       0x48, 0x4c, 0x50, 0x60, 0x74, 0x80):
                    item['value'] = hex(word(address))
                output_registers[hex(offset)] = item
    return dict(system_mode=mode[0], previous_mode=mode[1],
        card_admission=card_admission_snapshot(remote),
        processing_controller={hex(index * 4): hex(value) for index, value in enumerate(
            struct.unpack('<17I', remote.read(0x20100000, 68)))},
        processing_address_table={hex(index * 4): hex(value) for index, value in enumerate(
            struct.unpack('<32I', remote.read(0x20102880, 128)))},
        processing_ports=[[hex(value) for value in struct.unpack('<16I', remote.read(
            0x20102000 + index * 0x100, 64))] for index in range(2)],
        processing_address_banks=[[hex(value) for value in struct.unpack('<64I', remote.read(
            0x20102200 + index * 0x100, 256))] for index in range(2)],
        processing_sequence=[hex(value) for value in struct.unpack('<37I', remote.read(0x20102600, 148))],
        processing_dma=[dict(channel=channel, words=[hex(value) for value in struct.unpack(
            '<13I', remote.read(0x20100400 + channel * 0x40, 52))]) for channel in range(16)],
        mode1_output=dict(configuration=output_config.hex(), registers=output_registers),
        input_grid_configuration={hex(0x2006a2bc + index * 4): hex(value)
            for index, value in enumerate(struct.unpack('<24I', remote.read(0x2006a2bc, 96)))},
        driver_work_queue=[hex(value) for value in driver_queue],
        driver_pending_functions=driver_pending,
        application=dict(initialized=int.from_bytes(manager[:4], 'little'),
                         current=manager[16], requested=manager[17], state=manager[24]),
        engine_inputs=engines, lens_detection=lens_detection,
        engine_release_gpio=engine_release_gpio,
        controller_capture=controller_capture,
        resources=resources, capture_readiness=readiness, cores=cores,
        capture_tasks={name: task_wait_snapshot(remote, task) for name, task in
                       (('driver', 0xb23edde8), ('backend', 0xb21e2654),
                        ('image', 0xb238e654), ('processing', 0xb23ecc80),
                        ('image-bank0-control', 0xb1d52938),
                        ('image-bank1-control', 0xb1d52a8c),
                        ('input', 0xb25eeb78), ('image-stage0', 0xb1864a94),
                        ('image-stage0-final', 0xb1864a2c), ('image-stage1', 0xb1864afc),
                        ('image-stage2', 0xb1864bb0),
                        ('still-stage0', 0xb1864e64), ('still-stage1', 0xb1864e98))},
        input_context_queues=input_context_snapshot(remote),
        input_mask8_owner=hex(word(0xb25ef024)),
        auxiliary_image=auxiliary_image_snapshot(remote),
        primary_input=primary_input_snapshot(remote),
        display_delivery=display_delivery_snapshot(remote.read),
        image_work_queues=image_work_snapshot(remote),
        still_image_work=image_work_snapshot(remote, still=True),
        still_input_queues=still_queue_snapshot(remote),
        image_work_counters={hex(offset): hex(word(0xb18648b4 + offset))
                             for offset in range(0x24, 0x50, 4)},
        processing_bank_jobs=[processing_worker_snapshot(remote, task)
                              for task in (0xb1d52600, 0xb1d52648)],
        image_service=image_service_snapshot(remote),
        jpeg_encoder=dict(current_descriptor=hex(word(0xb1801eb8)),
                          accumulated_flags=hex(word(0xb1801eb0))),
        release_control=dict(header=list(remote.read(0xb186935c, 16)),
            words={hex(offset): hex(word(0xb186935c + offset))
                   for offset in (0x24, 0x28, 0x34, 0x38, 0x3c, 0x40, 0x44)}),
        input_channel_scan_count=24, input_channels=input_channels,
        input_completed_queues=[word(0xb26b3924 + index * 32 + 8) for index in range(4)],
        input_completed_heads=completed_heads,
        input_interrupts=dict(
            controls={hex(offset): hex(word(0x20068000 + offset))
                      for offset in (0, 4, 8, 0x10, 0x14, 0x18, 0x100, 0x104, 0x140, 0x144)},
            banks=[dict(mask=hex(word(0x20068200 + index * 32)),
                        status=hex(word(0x20068210 + index * 32))) for index in range(8)],
            callbacks={hex(index * 4): hex(value) for index, value in enumerate(
                struct.unpack('<12I', remote.read(0xb18067e4, 48)))}),
        input_state=dict(state_5=remote.read(0xb1887d75, 1)[0],
                         state_6=remote.read(0xb1887d76, 1)[0],
                         finite_frames=list(remote.read(0xb1888146, 2)),
                         processing_flags=hex(word(0xb26b38cc)),
                         finite_request=hex(word(0xb1887dd8)),
                         finite_queue_count=word(0xb25eebcc),
                         mode1_output_latches=[word(0xb26b38d8 + index * 4) for index in range(2)],
                         configured_mask=hex(word(0xb1887dcc)),
                         required_mask=hex(word(0xb1887dd0)),
                         processing_masks=[hex(word(0xb26b38b4 + index * 4)) for index in range(4)]),
        delay_enable=hex(word(0x2c011000)), delay_channels=delay_channels,
        action_state=state, handler_object=hex(handler_object),
        action_handler=hex(word(handler_object + 0x14)),
        release_gate=word(0xb1821e84), event1_pending=word(0xb201bdd4),
        release_action_context=dict(byte_b202c017=remote.read(0xb202c017, 1)[0],
                                    byte_b202c97a=remote.read(0xb202c97a, 1)[0],
                                    option41=word(0xb202bcd0), option42=word(0xb202bcd4)),
        event1_notifications=[hex(notification) for notification, event in
                              struct.iter_unpack('<II', notifications) if event == 1],
        capture_state=list(remote.read(0xb23f6a80, 2)),
        operation14_callback=hex(word(0xb23f701c)), status_codes=codes,
        operation15_callback=hex(word(0xb23f7020)),
        operation18_callback=hex(word(0xb23f702c)),
        operation19_callback=hex(word(0xb23f7030)),
        capture_field_14=hex(word(0xb23f6a90)),
        capture_driver_state=remote.read(0xb1868af1, 1)[0],
        capture_driver_pending_state=remote.read(0xb1868afa, 1)[0],
        capture_driver_mode=remote.read(0xb1868af7, 1)[0],
        capture_driver_context_count=word(0xb1868b58),
        capture_driver_finish_comparison_word=hex(word(0xb1868c34)),
        capture_driver_input_flags=hex(word(0xb1868ca0)),
        context_kind_property_1676=word(0xb2551954),
        capture_stop_ready_flags=hex(word(0xb1868b64)),
        stop_queue_count=word(0xb23ef3d0),
        processing_command=remote.read(0xb1868310, 1)[0],
        processing_state=remote.read(0xb1868311, 1)[0],
        processing_field_24=word(0xb1868334),
        processing_output_kind=remote.read(0xb23ed190, 1)[0],
        processing_output_mode=remote.read(0xb23ed184, 1)[0],
        gpio_adapter=dict(mode=remote.read(0xb18a7920, 1)[0],
                          timer_active=word(0xb18a7924),
                          output_descriptor=hex(word(0xb18a7928)),
                          input_descriptor=hex(word(0xb18a792c))),
        gpio_irq=dict(mask=hex(word(0x0426f000)), pending=hex(word(0x0426f008)),
                      polarity=hex(word(0x0426f014))),
        delegate_state=remote.read(0xb1868510, 1)[0],
        delegate_kind=remote.read(0xb1868511, 1)[0],
        sampling_control=[hex(word(0x200632e0 + i * 4)) for i in range(2)],
        sampling_header=list(remote.read(0xb1868628, 0x100)),
        sampling_counter_context=list(remote.read(0xb1868880, 0x50)),
        sampling_registers=dict(control={hex(offset): hex(word(0x20060000 + offset))
            for offset in (*range(0, 0x3c, 4), 0x40, 0x44, 0x4c, 0x50)},
            outputs=[[hex(x) for x in struct.unpack('<10I', remote.read(address, 40))]
                     for address in (0x200630d0, 0x20063110)]),
        counter_ticks=int.from_bytes(remote.read(0x04266008, 8), 'little'),
        counter_frequency=word(0x04266010),
        input_format=hex(word(0x20068500)),
        input_geometry=[hex(value) for value in geometry[:3]],
        input_geometry_registers={hex(0x20069500 + index * 4): hex(value)
                                  for index, value in enumerate(geometry)},
        switch_words=[hex(word(0xb25eaeac + i * 4)) for i in range(3)])


def lcd_snapshot(machine):
    """Summarize the native LCD plane without exporting its pixel payload."""
    with machine.io:
        machine.qmp.command('stop')
        try:
            size = machine._words(0x20144204, 1)[0]
            width, height = size & 0xffff, (size >> 16) & 0x3fff
            planes = [machine._words(address, 1)[0] for address in (0x20144210, 0x20144220)]
            result = dict(width=width, height=height, planes=[hex(value) for value in planes],
                          registers={hex(offset): hex(machine._words(0x20144000 + offset, 1)[0])
                                     for offset in (0x200, 0x204, 0x240, 0x250,
                                                    0x410, 0x414, 0x418, 0x41c, 0x420, 0x424,
                                                    0x600, 0x604)})
            candidates = {}
            for offset in (0x210, 0x220, 0x2440, 0x24c0, 0x3440, 0x34c0):
                addresses = machine._words(0x20144000 + offset, 4)
                for index, address in enumerate(addresses):
                    if 0xb0000000 <= address <= 0xf0000000 - 4096:
                        key = hex(address)
                        if key not in candidates:
                            data = machine._bytes(address, 4096)
                            candidates[key] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                                   unique_bytes=len(set(data)), minimum=min(data), maximum=max(data),
                                                   slots=[])
                        candidates[key]['slots'].append(hex(offset + index * 4))
            result['candidate_buffer_heads'] = candidates
            if not (0 < width <= 4096 and 0 < height <= 4096):
                return dict(result, configured=False)
            for plane in planes:
                if 0xb0000000 <= plane <= 0xf0000000 - width * height:
                    data = machine._bytes(plane, width * height)
                    return dict(result, configured=True, sampled_plane=hex(plane),
                        byte_count=len(data), sha256=hashlib.sha256(data).hexdigest(),
                        unique_bytes=len(set(data)), minimum=min(data), maximum=max(data))
            return dict(result, configured=False)
        finally:
            machine.qmp.command('cont')


def input_dma_snapshot(machine):
    with machine.io:
        machine.qmp.command('stop')
        try:
            paths = ['/machine/unattached/' + name for name in machine.config_names]
            path = next(path for path in paths if machine.qmp.command(
                'qom-get', dict(path=path, property='master-role')))
            count = machine.qmp.command('qom-get', dict(path=path, property='input-dma-count'))
            address = machine.qmp.command('qom-get', dict(path=path, property='input-dma-address'))
            stride = machine._words(0x20069a08, 1)[0]
            result = dict(frames=count, address=hex(address), stride=stride)
            result['running_mask'] = hex(machine.qmp.command('qom-get',
                dict(path=path, property='input-running')))
            result['frame_ticks'] = machine.qmp.command('qom-get',
                dict(path=path, property='frame-sync-count'))
            result['startup_grid_frames'] = machine.qmp.command('qom-get',
                dict(path=path, property='input-grid-count'))
            result['startup_grid_address'] = hex(machine.qmp.command('qom-get',
                dict(path=path, property='input-grid-address')))
            result['processing_frames'] = machine.qmp.command('qom-get',
                dict(path=path, property='processing-dma-count'))
            result['processing_grids'] = machine.qmp.command('qom-get',
                dict(path=path, property='processing-grid-count'))
            result['auxiliary_jobs'] = machine.qmp.command('qom-get',
                dict(path=path, property='aux-image-process-count'))
            result['primary_frames'] = machine.qmp.command('qom-get',
                dict(path=path, property='primary-input-dma-count'))
            for key, name in (('primary_address', 'primary-input-dma-address'),
                              ('primary_second_address', 'primary-input-second-dma-address')):
                result[key] = hex(machine.qmp.command('qom-get', dict(path=path, property=name)))
            if result['primary_frames']:
                primary = int(result['primary_address'], 16)
                peer = int(result['primary_second_address'], 16)
                first_stride = int.from_bytes(machine._bytes(0x20069808, 4), 'little')
                full_stride = int.from_bytes(machine._bytes(0x20069908, 4), 'little')
                require((first_stride, full_stride) in ((4224, 12432), (4928, 14512)),
                        'Unexpected completed primary input strides')
                result['primary_row_strides'] = dict(first=first_stride, full=full_stride)
                result['primary_samples'] = []
                for owner, cpu, target, length in (('master', 0, primary, first_stride),
                                                  ('slave', 2, peer, 5472 * first_stride // 2816)):
                    data = machine._bytes(target, length, cpu=cpu)
                    result['primary_samples'].append(dict(owner=owner, cpu=cpu,
                        address=hex(target), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                        unique_bytes=len(set(data)), minimum=min(data), maximum=max(data)))
            if count and address and 0 < stride <= 16384:
                data = machine._bytes(address, stride)
                result['first_row'] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                           unique_bytes=len(set(data)), minimum=min(data), maximum=max(data))
            return result
        finally:
            machine.qmp.command('cont')


def primary_mapping_request(remote, domain, address, length):
    result = dict(domain=domain, address=hex(address), bytes=length)
    pointer, count = struct.unpack('<2I', remote.read(0xb1808948, 8))
    if 0 < count <= 8 and 0xb0000000 <= pointer <= 0xb5f00000 - count * 24:
        result['native_windows'] = [[hex(value) for value in struct.unpack(
            '<6I', remote.read(pointer + index * 24, 24))] for index in range(count)]
    if all(name in remote.register_numbers for name in ('TTBR0_S', 'TTBCR_S')) and \
            remote.read_register('TTBCR_S') == 0:
        ttbr = remote.read_register('TTBR0_S')
        result['sections'] = []
        for source in sorted({address, address + length - 1,
                              0xbad0a000, 0xbc0a0000, 0xbd1e0000, 0xbee7c0ff}):
            if not 0 <= source <= 0xffffffff:
                continue
            descriptor = int.from_bytes(remote.read(
                (ttbr & 0xffffc000) + (source >> 20) * 4, 4), 'little')
            row = dict(address=hex(source), descriptor=hex(descriptor))
            if descriptor & 3 == 2:
                row['physical_address'] = hex((descriptor & 0xfff00000) | (source & 0xfffff))
            result['sections'].append(row)
    return result


def observe(machine, seconds, playback=False, local_stop_events=False, returning=False,
            gpio_handshake_events=False, watch_read=None, watch_write=None, frame_notify=False,
            reconfigure=False, tail_frame_events=False, mode1_frame_events=False,
            watch_bytes=4, watch_count=1, shutter_on_preview=False, half_before_full=False,
            input_boundary_events=False, shutter_on_ready=False, capture_submit_on_ready=False,
            capture_wait_idle=False, application_only=False, shutter_click=False,
            image_work_events=False, capture_focus=False, capture_counter_seconds=None,
            body_state_events=False,
            body_capture_events=False, body_input_events=False, body_compute_events=False,
            body_system_events=False,
            controller_step_trigger=False, capture_exposure=None, capture_jpeg=False, capture_storage=0,
            capture_format_3800=False):
    with machine.io:
        machine.qmp.command('stop')
    remote = Remote(machine.gdb_port)
    armed = {ACTION: 'application-action'}
    if playback:
        armed.update(AFTER_PLAYBACK)
    if returning:
        armed = dict(RETURN_POINTS)
    if reconfigure:
        armed.update({address: label for address, label in RECONFIGURE_POINTS.items()
                      if not application_only or address in
                      (0x103e1dea, 0x1023c5dc)})
    elif shutter_on_preview or shutter_on_ready or capture_submit_on_ready:
        armed[0x103e1dea] = 'reconfigure-display-frame-submit'
    if input_boundary_events:
        armed.update({0x102389c2: 'input-boundary-wait',
                      0x102389c6: 'input-boundary-wait-return'})
    if frame_notify and not (application_only or capture_focus):
        armed.update({0x10238d4a: 'input-frame-task',
                      0x10238c40: 'input-frame-dequeue',
                      0x1023c960: 'input-completed-enqueue',
                      0x1023beec: 'input-frame-context-enqueue',
                      0x1022e2e0: 'input-frame-notification',
                      0x1022e0ae: 'input-context-wait-update',
                      0x1022e154: 'input-context-wait-stored',
                      0x1022e1aa: 'input-context-all-waits-complete',
                      0x10321d80: 'input-context-driver-complete',
                      0x10321d94: 'input-context-output-check',
                      0x10321dbe: 'input-context-output-enqueue',
                      0x1032206e: 'input-context-special-job-check',
                      0x10322126: 'input-context-special-job-found',
                      0x10322250: 'input-context-special-job-submit',
                      0x10325304: 'input-context-header-construction',
                      0x10233570: 'input-context-frame-prepare',
                      0x10398206: 'processing-frame-parameters',
                      0x10233b9c: 'processing-frame-parameters-return',
                      0x10232154: 'input-context-frame-configure',
                      0x102313ea: 'input-ready-worker',
                      0x10231472: 'input-ready-context-selected',
                      0x10231486: 'input-ready-normal-branch',
                      0x102314e6: 'input-ready-state-check',
                      0x102315c2: 'input-ready-notification',
                      0x102315c4: 'input-ready-notification-call',
                      0x103279c0: 'input-ready-notification-decision',
                      0x10327c88: 'input-ready-queue-submit',
                      0x10319d88: 'input-driver-queue-result',
                      0x103191c4: 'input-ready-queue-dispatch',
                      0x10326676: 'input-ready-driver-producer',
                      0x103231b2: 'input-driver-state-transition',
                      0x1032a792: 'input-context-consumer-release',
                      0x10321e22: 'input-context-consumer-return',
                      0x10321e24: 'input-context-driver-output-return'})
    if capture_submit_on_ready:
        armed.update({0x10239c34: 'primary-input-builder',
                      0x1038848a: 'primary-input-remap-request'})
    if application_only or capture_focus:
        armed.update({0x103ba6ea: 'body-native-capture-api',
                      0x1022aaae: 'body-release-engine-gpio-callback',
                      0x103ba164: 'body-native-capture-release',
                      0x103f36fa: 'body-operation59-api',
                      0x103f19c0: 'body-operation59-task',
                      0x104e1690: 'release-configuration-timer-callback',
                      **ENGINE_ABORT_POINTS})
    if capture_focus:
        armed.update(CAPTURE_SLAVE_INIT_POINTS)
    image_work_armed = False
    body_status_armed = False
    body_capture_armed = False
    body_periodic_operations = {}
    body_input_armed = False
    body_input_seen = {}
    body_input_samples = {}
    body_compute_armed = False
    body_system_armed = False
    records = []
    hits = {}
    callback_hits = 0
    watch_address = watch_read if watch_read is not None else watch_write
    watch_type = 3 if watch_read is not None else 2
    memory_watch_armed = False
    watched_count = 0
    started = time.monotonic()
    breakpoints_installed = False
    capture_caller = None
    capture_input_path = None
    capture_work_requests = set()
    capture_work_parameters = {}
    controller_step_trigger_sent = False
    try:
        before = snapshot(remote)
        if body_compute_events:
            before['master_compute'] = master_compute_snapshot(remote)
        if capture_focus:
            before['peer_input'] = peer_input_snapshot(remote)
        if capture_submit_on_ready:
            from tools.native_capture_caller import NativeCaptureCaller
            capture_caller = NativeCaptureCaller(remote, exposure=capture_exposure,
                                                 jpeg=capture_jpeg, storage=capture_storage,
                                                 format_3800=capture_format_3800)
            if capture_focus:
                selected = {0x1020f8dc, 0x1032385a, 0x10233222, 0x10233250,
                            0x103234e8, 0x10322e3e, 0x10322ef8, 0x10322f30,
                            0x10322fd4, 0x10323500, 0x1031dd00, 0x103e9d24,
                            0x102389c2, 0x102389c6}
                capture_caller.points = {address: label for address, label in
                    capture_caller.points.items() if address not in capture_caller.ui_points or
                    address in selected}
                capture_caller.ui_points = {address: label for address, label in
                    capture_caller.ui_points.items() if address in selected}
            armed.update(capture_caller.points)
        for address in armed:
            remote.breakpoint(address)
        breakpoints_installed = True
        tail_events = []
        mode1_events = []
        def pulse_mode1():
            for level in (1, 0):
                machine._qtest(f'set_irq_in /machine/unattached/{machine.config_names[0]} '
                               f'input-event 103 {level}')
            mode1_events.append(103)
        if mode1_frame_events:
            require(before['capture_driver_state'] == 4 and
                    before['input_state']['finite_frames'][1] == 1 and
                    int(before['input_state']['processing_flags'], 16) & 4,
                    'Mode 1 event experiment requires the observed finite input request')
            pulse_mode1()
        if tail_frame_events:
            require(before['capture_driver_state'] == 4 and
                    before['input_interrupts']['controls']['0x8'] == '0x10',
                    'Tail event experiment requires the observed reconfiguration state')
            for line in (0, 6):
                for level in (1, 0):
                    machine._qtest(f'set_irq_in /machine/unattached/{machine.config_names[0]} '
                                   f'input-event {line} {level}')
                tail_events.append(line)
        if watch_address is not None:
            require(remote.command(f'Z{watch_type},{watch_address:x},{watch_bytes:x}') == 'OK',
                    'Memory watchpoint rejected')
            memory_watch_armed = True
        if not (shutter_on_preview or shutter_on_ready or capture_submit_on_ready):
            machine.set_key(24 if returning else 8 if playback else 25, 0)
        preview_press_sent = False
        idle_preview_seen = False
        preview_half_tick = None
        preview_full_tick = None
        click = dict(requested=shutter_click, released=False)
        boundary_frame = 0
        boundary_path = None
        if input_boundary_events:
            paths = ['/machine/unattached/' + name for name in machine.config_names]
            boundary_path = next(path for path in paths if machine.qmp.command(
                'qom-get', dict(path=path, property='master-role')))
            boundary_frame = machine.qmp.command('qom-get',
                dict(path=boundary_path, property='input-dma-count'))
        deadline = started + seconds
        checkpointed = started
        while time.monotonic() < deadline and (armed or memory_watch_armed):
            machine.heartbeat()
            if (capture_caller and capture_caller.report['caller_returned'] and
                    capture_caller.report.get('api_status') not in (None, 0)):
                capture_caller.report['observation_ended_for_rejection'] = True
                break
            if (capture_caller and capture_exposure is not None and
                    capture_caller.report['caller_returned'] and
                    not capture_caller.report['settings_fixture']['ready']):
                break
            if capture_focus and time.monotonic() - checkpointed >= 15:
                remote.select_thread(1)
                checkpoint_ticks = int.from_bytes(remote.read(0x04266008, 8), 'little')
                checkpoint = machine.work / 'capture-focus-checkpoint.json'
                temporary = checkpoint.with_suffix('.tmp')
                temporary.write_text(json.dumps(dict(incomplete=True, before=before,
                    records=records, diagnostic_capture=capture_caller.report,
                    counter_ticks=checkpoint_ticks), indent=2),
                    encoding='utf-8')
                temporary.replace(checkpoint)
                checkpointed = time.monotonic()
            if capture_counter_seconds is not None and capture_caller.report['triggered']:
                remote.select_thread(1)
                ticks = int.from_bytes(remote.read(0x04266008, 8), 'little')
                if ticks - capture_caller.report['trigger_counter_ticks'] >= (
                        capture_counter_seconds * before['counter_frequency']):
                    break
            if shutter_click and preview_full_tick is not None and not click['released']:
                remote.select_thread(1)
                ticks = int.from_bytes(remote.read(0x04266008, 8), 'little')
                if ticks - preview_full_tick >= before['counter_frequency'] // 4:
                    machine.set_key(25, 1)
                    machine.set_key(24, 1)
                    click.update(released=True, release_ticks=ticks,
                        held_counter_seconds=(ticks - preview_full_tick) / before['counter_frequency'])
            remote.sock.settimeout(min(1, max(0.2, deadline - time.monotonic())))
            try:
                reply = remote.command('vCont;c')
            except TimeoutError:
                remote.sock.settimeout(15)
                remote.interrupt()
                continue
            match = re.search(r'thread:([0-9a-f]+);', reply)
            require(match is not None, 'Missing stop thread')
            thread = int(match[1], 16)
            remote.select_thread(thread)
            registers = remote.regs()
            pc = remote.get(registers, 'pc')
            watched = re.search(r'(?:rwatch|watch):([0-9a-f]+);', reply)
            watched_address = int(watched[1], 16) if watched else None
            if watched_address is not None and watch_address <= watched_address < watch_address + watch_bytes:
                record = dict(entry='watched-read' if watch_type == 3 else 'watched-write',
                    pc=hex(pc), thread=thread,
                    address=hex(watched_address), registers={name: hex(remote.get(registers, name))
                        for name in ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                                     'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'cpsr')})
                record['address_kind'] = 'reported-watch-window'
                window_before = None
                if watch_type == 2 and watch_bytes > 4 and 0x20100000 <= watch_address < 0x20110000 - watch_bytes:
                    window_before = remote.read(watch_address, watch_bytes)
                if pc == 0x10361044:
                    record['saved_return'] = hex(int.from_bytes(remote.read(
                        remote.get(registers, 'sp'), 4), 'little'))
                if 0x20100000 <= watched_address < 0x2014f000:
                    record['stack_words'] = [hex(value) for value in struct.unpack(
                        '<32I', remote.read(remote.get(registers, 'sp'), 128))]
                read_watched_word = watch_type == 2 and (
                    0xb1800000 <= watched_address <= 0xb5effffc or
                    0x20100000 <= watched_address <= 0x2010fffc)
                if read_watched_word:
                    record['previous_window_word' if watch_bytes > 4 else 'previous_word'] = hex(
                        int.from_bytes(remote.read(watched_address, 4), 'little'))
                if pc in (0x1024ffb4, 0x1024ffda):
                    descriptor = remote.get(registers, 'r5') - 0x14
                    columns, rows = struct.unpack('<HH', remote.read(descriptor + 0x1e, 4))
                    record['grid_buffer'] = dict(descriptor=hex(descriptor),
                        columns=columns, rows=rows, sample_bytes=2,
                        row_bytes=(columns * 2 + 15) & ~15,
                        sample_address=hex(int.from_bytes(remote.read(descriptor + 0x2c, 4), 'little')),
                        field_28=hex(int.from_bytes(remote.read(descriptor + 0x28, 4), 'little')),
                        field_30=hex(int.from_bytes(remote.read(descriptor + 0x30, 4), 'little')))
                if 'TTBR0_S' in remote.register_numbers:
                    ttbr = remote.read_register('TTBR0_S')
                    section_address = (ttbr & 0xffffc000) + (watched_address >> 20) * 4
                    section = int.from_bytes(remote.read(section_address, 4), 'little')
                    record['translation'] = dict(ttbr0=hex(ttbr),
                        section_address=hex(section_address), section=hex(section))
                    if section & 3 == 2:
                        record['translation']['section_physical_address'] = hex(
                            (section & 0xfff00000) | (watched_address & 0xfffff))
                records.append(record)
                require(remote.command(f'z{watch_type},{watch_address:x},{watch_bytes:x}') == 'OK',
                        'Memory watchpoint removal failed')
                memory_watch_armed = False
                remote.sock.settimeout(15)
                remote.command(f'vCont;s:{thread:x}')
                if read_watched_word:
                    record['current_window_word' if watch_bytes > 4 else 'current_word'] = hex(
                        int.from_bytes(remote.read(watched_address, 4), 'little'))
                if window_before is not None:
                    window_after = remote.read(watch_address, watch_bytes)
                    record['changed_window_words'] = [dict(address=hex(watch_address + index * 4),
                        previous=hex(previous), current=hex(current))
                        for index, (previous, current) in enumerate(zip(
                            struct.unpack('<' + 'I' * (watch_bytes // 4), window_before),
                            struct.unpack('<' + 'I' * (watch_bytes // 4), window_after))) if previous != current]
                watched_count += 1
                if watched_count >= watch_count:
                    break
                require(remote.command(f'Z{watch_type},{watch_address:x},{watch_bytes:x}') == 'OK',
                        'Memory watchpoint rearm failed')
                memory_watch_armed = True
                continue
            require(pc in armed, f'Unexpected stop at {pc:#x}')
            repeat = thread > 2 or pc in CAPTURE_SLAVE_POINTS
            if pc in ENGINE_ABORT_POINTS and thread <= 4:
                prefetch = pc in (0x1010000c, 0x1003410c)
                record = dict(entry=armed[pc], pc=hex(pc), thread=thread,
                    engine='master' if thread <= 2 else 'slave',
                    registers={name: hex(remote.get(registers, name)) for name in
                        ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                         'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'cpsr')},
                    faults={name: hex(remote.read_register(name)) for name in
                            ('DFAR_S', 'IFAR_S', 'DFSR_S', 'IFSR_S')},
                    translation={name: hex(remote.read_register(name)) for name in
                        ('TTBR0_S', 'TTBR1_S', 'TTBCR_S') if name in remote.register_numbers},
                    faulting_pc=hex((remote.get(registers, 'lr') - (4 if prefetch else 8)) & 0xffffffff))
                translation = record['translation']
                if translation.get('TTBCR_S') == '0x0' and 'TTBR0_S' in translation:
                    address = int(record['faults']['IFAR_S' if prefetch else 'DFAR_S'], 16)
                    l1_address = (int(translation['TTBR0_S'], 16) & 0xffffc000) + (address >> 20) * 4
                    try:
                        l1 = int.from_bytes(remote.read(l1_address, 4), 'little')
                        translation.update(l1_address=hex(l1_address), l1=hex(l1))
                        if l1 & 3 == 2:
                            translation['physical_address'] = hex((l1 & 0xfff00000) | (address & 0xfffff))
                        elif l1 & 3 == 1:
                            l2_address = (l1 & 0xfffffc00) + ((address >> 12) & 255) * 4
                            l2 = int.from_bytes(remote.read(l2_address, 4), 'little')
                            translation.update(l2_address=hex(l2_address), l2=hex(l2))
                            if l2 & 2:
                                translation['physical_address'] = hex((l2 & 0xfffff000) | (address & 0xfff))
                            elif l2 & 3 == 1:
                                translation['physical_address'] = hex((l2 & 0xffff0000) | (address & 0xffff))
                    except ValueError as error:
                        translation['read_error'] = str(error)
                if thread in (3, 4):
                    pointer = remote.get(registers, 'r4')
                    if 0xc1000000 <= pointer <= 0xc5ffffc0:
                        record['r4_object'] = dict(address=hex(pointer), words=[hex(value) for value in
                            struct.unpack('<16I', remote.read(pointer, 64))])
                remote.select_thread(1)
                record['counter_ticks'] = int.from_bytes(remote.read(0x04266008, 8), 'little')
                records.append(record)
                break
            if thread == 5 and pc in CAPTURE_CONTROLLER_POINTS:
                record = dict(entry=armed[pc], pc=hex(pc), thread=thread,
                    registers={name: hex(remote.get(registers, name)) for name in
                               ('r0', 'r1', 'r2', 'r3', 'lr')},
                    channel9_header=list(remote.read(0x2001359c, 6)),
                    channel9_words=[hex(value) for value in
                        struct.unpack('<10I', remote.read(0x200135b0, 40))],
                    backend_header=list(remote.read(0x2001756c, 24)),
                    backend_words=[hex(value) for value in
                        struct.unpack('<5I', remote.read(0x20017584, 20))],
                    backend_request=list(remote.read(0x2000e8c0, 6)))
                if pc in (0x080368ce, 0x08036986):
                    def controller_word(address):
                        return int.from_bytes(remote.read(address, 4), 'little')
                    record['step_input'] = dict(
                        port=controller_word(0x40013810) & 15,
                        mask=hex(controller_word(0x40013c00)),
                        rising=hex(controller_word(0x40013c08)),
                        falling=hex(controller_word(0x40013c0c)),
                        pending=hex(controller_word(0x40013c14)),
                        original_level=(controller_word(0x40021810) >> 8) & 1)
                    if pc == 0x080368ce and controller_step_trigger and not controller_step_trigger_sent:
                        source = record['step_input']
                        require(source['port'] == 6 and int(source['mask'], 16) & 0x100 and
                                (int(source['rising'], 16) | int(source['falling'], 16)) & 0x100 and
                                not int(source['pending'], 16) & 0x100,
                                'Controller G8 step input is not armed and clear')
                        original = source['original_level']
                        for level in (1 - original, original):
                            machine._qtest(f'set_irq_in /machine/unattached/{machine.gpio_names[6]} '
                                           f'unnamed-gpio-in 8 {level}')
                        controller_step_trigger_sent = True
                        record['controller_step_trigger_host_supplied'] = True
                        capture_caller.report['controller_step_trigger_host_supplied'] = True
                if pc == 0x080369d0:
                    pointer = remote.get(registers, 'r0')
                    if 0x20000000 <= pointer <= 0x2003fff8:
                        length = int.from_bytes(remote.read(pointer, 2), 'little')
                        payload = int.from_bytes(remote.read(pointer + 4, 4), 'little')
                        record['request_length'] = length
                        if length and 0x20000000 <= payload < 0x20040000:
                            record['request_code'] = remote.read(payload, 1)[0]
                remote.select_thread(1)
                record['counter_ticks'] = int.from_bytes(remote.read(0x04266008, 8), 'little')
                remote.select_thread(thread)
                records.append(record)
                hits[pc] = hits.get(pc, 0) + 1
                repeat = hits[pc] < (32 if pc == 0x08034de0 else 8)
            if thread in (3, 4) and pc in CAPTURE_SLAVE_POINTS:
                record = dict(entry=armed[pc], pc=hex(pc), thread=thread,
                    registers={name: hex(remote.get(registers, name)) for name in
                        ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                         'r8', 'r9', 'r10', 'r11', 'lr')})
                keep = True
                if pc == 0x10129faa:
                    pointer = remote.get(registers, 'r1')
                    keep = remote.get(registers, 'r0') == 0x42070001 and 0xc1000000 <= pointer <= 0xc81fffe0
                    if keep:
                        words = struct.unpack('<8I', remote.read(pointer, 32))
                        record['message_words'] = [hex(value) for value in words]
                        keep = words[0] in (5, 10)
                if keep:
                    remote.select_thread(1)
                    record['counter_ticks'] = int.from_bytes(remote.read(0x04266008, 8), 'little')
                    remote.select_thread(thread)
                    records.append(record)
                    hits[pc] = hits.get(pc, 0) + 1
                repeat = not keep or hits[pc] < 8
            if thread <= 2 and pc not in CAPTURE_SLAVE_POINTS:
                record = dict(entry=armed[pc], pc=hex(pc), thread=thread,
                    registers={name: hex(remote.get(registers, name)) for name in
                               ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'lr')})
                if capture_focus and pc == 0x1023938c:
                    record['peer_input'] = peer_input_snapshot(remote, thread)
                if capture_caller:
                    return_pc = capture_caller.observe(pc, registers)
                    if return_pc is not None:
                        require(return_pc not in armed, 'Capture return observation overlaps a breakpoint')
                        armed[return_pc] = 'diagnostic-capture-task-return'
                        remote.breakpoint(return_pc)
                    if capture_focus and armed[pc] == 'diagnostic-capture-caller':
                        paths = ['/machine/unattached/' + name for name in machine.config_names]
                        capture_input_path = next(path for path in paths if machine.qmp.command(
                            'qom-get', dict(path=path, property='master-role')))
                        for address, label in (CAPTURE_INPUT_POINTS | CAPTURE_CONTROLLER_POINTS |
                                               CAPTURE_SLAVE_POINTS).items():
                            if address in CAPTURE_SLAVE_INIT_POINTS:
                                continue
                            require(address not in armed, 'Capture input observation overlaps a breakpoint')
                            armed[address] = label
                            remote.breakpoint(address)
                keep = not (pc == 0x10319d88 and remote.get(registers, 'r4') != 0x10326677 or
                            pc == 0x103191c4 and not reconfigure and remote.get(registers, 'r1') != 0x10326677 or
                            pc == 0x103231b2 and remote.get(registers, 'r0') == remote.get(registers, 'r7'))
                if pc == 0x1038848a:
                    domain = remote.get(registers, 'r0')
                    keep, repeat = domain == 2, domain != 2
                    if keep:
                        record['mapping_request'] = primary_mapping_request(remote, domain,
                            remote.get(registers, 'r1'), remote.get(registers, 'r2'))
                if pc == 0x10239c34:
                    argument = remote.get(registers, 'r0')
                    full, partial = struct.unpack('<2I', remote.read(argument + 0xc, 8))
                    record['primary_headers'] = []
                    for kind, pointer in (('full', full), ('partial', partial)):
                        row = dict(kind=kind, pointer=hex(pointer))
                        if 0xb0000000 <= pointer <= 0xb5efffc0:
                            header = remote.read(pointer, 0x38)
                            allocation = struct.unpack_from('<I', header, 4)[0]
                            row.update(format=header[0x24],
                                width=struct.unpack_from('<H', header, 0x28)[0],
                                height=struct.unpack_from('<H', header, 0x2a)[0],
                                target=hex(struct.unpack_from('<I', header, 0x34)[0]))
                            if 0xb0000000 <= allocation <= 0xb5effff8:
                                source, length = struct.unpack('<2I', remote.read(allocation, 8))
                                row['allocation'] = primary_mapping_request(remote, 2, source, length)
                                row['allocation']['descriptor'] = hex(allocation)
                                if allocation <= 0xb5efffef:
                                    row['allocation']['fields'] = {hex(offset): hex(int.from_bytes(
                                        remote.read(allocation + offset, 4), 'little')) for offset in (8, 12)}
                                    row['allocation']['field_0x10_byte'] = remote.read(allocation + 16, 1)[0]
                        record['primary_headers'].append(row)
                if capture_caller and pc in capture_caller.ui_points:
                    record['ui_capture'], keep, repeat = capture_caller.ui_observation(pc, registers)
                    if (capture_wait_idle and idle_preview_seen and not preview_press_sent and
                            pc == 0x1020f8dc and keep and
                            not record['ui_capture']['blocking_resources'] and
                            int.from_bytes(remote.read(0xb1821e84, 4), 'little') == 0):
                        capture_caller.trigger()
                        preview_press_sent = True
                        record['diagnostic_capture_after_idle_event'] = True
                if keep and pc == 0x103231b2:
                    record['state_transition'] = dict(previous=remote.get(registers, 'r7'),
                        next=remote.get(registers, 'r0'), request=remote.get(registers, 'r10'))
                if pc == 0x1046c3c2:
                    record['display_configuration'] = remote.read(remote.get(registers, 'r1'), 24).hex()
                if input_boundary_events and pc == 0x102389c2:
                    requested = remote.get(registers, 'r1')
                    routes = ((0x100000, 0, 3), (0x200000, 0, 4),
                              (0x800000, 3, 5), (0x1000000, 3, 0), (0x4000000, 4, 7))
                    frames = machine.qmp.command('qom-get',
                        dict(path=boundary_path, property='input-dma-count'))
                    lines = []
                    if requested and not requested & ~0x5b00000 and frames > boundary_frame:
                        selected = [(bank, bit) for mask, bank, bit in routes if requested & mask]
                        enabled = all(int.from_bytes(remote.read(0x20068200 + bank * 32, 4),
                                                     'little') & 1 << bit for bank, bit in selected)
                        if enabled:
                            for bank, bit in selected:
                                line = bank * 32 + bit
                                for level in (1, 0):
                                    machine._qtest(f'set_irq_in /machine/unattached/{machine.config_names[0]} '
                                                   f'input-event {line} {level}')
                                lines.append(line)
                            boundary_frame = frames
                    record['input_boundary'] = dict(requested=hex(requested), raw_frames=frames,
                                                     injected_lines=lines)
                if input_boundary_events and pc in (0x102389c2, 0x102389c6):
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < 64
                if pc == 0x103e1d30:
                    pointer = remote.get(registers, 'r5')
                    record['display_frame'] = dict(address=hex(pointer),
                        words={hex(index * 4): hex(value) for index, value in enumerate(
                            struct.unpack('<34I', remote.read(pointer, 0x88)))})
                if pc == 0x102692ca:
                    surface = remote.get(registers, 'r3')
                    record['capture_surface'] = dict(address=hex(surface),
                        words={hex(index * 4): hex(value) for index, value in enumerate(
                            struct.unpack('<7I', remote.read(surface, 0x1c)))})
                    context = remote.get(registers, 'r4')
                    if 0xb2c00000 <= context < 0xb5effeb0:
                        record['capture_context'] = dict(address=hex(context),
                            words={hex(offset): hex(int.from_bytes(remote.read(context + offset, 4), 'little'))
                                   for offset in (0, 4, 8, 0xc, 0x10, 0x30, 0x68, 0x6c, 0x70,
                                                  0x74, 0x90, 0x94, 0x98, 0x9c, 0xa0, 0xa4, 0x144, 0x148)})
                        objects = {}
                        for offset in (0x68, 0x6c, 0x70, 0x74, 0x9c, 0xa0, 0xa4):
                            pointer = int.from_bytes(remote.read(context + offset, 4), 'little')
                            if 0xb2c00000 <= pointer < 0xb5efffbc:
                                objects[hex(offset)] = dict(address=hex(pointer),
                                    words={hex(index * 4): hex(value) for index, value in enumerate(
                                        struct.unpack('<17I', remote.read(pointer, 0x44)))})
                        record['capture_buffer_objects'] = objects
                if pc in (0x103bded0, 0x103bd07c):
                    module = remote.get(registers, 'r0' if pc == 0x103bded0 else 'r1')
                    if module < 128:
                        base, callback = struct.unpack('<2I', remote.read(0x1078a2a0 + module * 8, 8))
                        record['processing_module'] = dict(index=module, base=hex(base), callback=hex(callback))
                        if 0x20100100 <= base < 0x20110000:
                            values = struct.unpack('<8I', remote.read(base, 32))
                            record['processing_module']['registers'] = [hex(value) for value in values]
                            pointer = remote.get(registers, 'r1') if pc == 0x103bded0 else values[4]
                            record['processing_module']['parameters'] = hex(pointer)
                            if 0xb1800000 <= pointer < 0xb5efff00 or 0xb0100000 <= pointer < 0xb08fff00:
                                data = remote.read(pointer, 256)
                                record['processing_module']['parameter_summary'] = dict(
                                    bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                if pc == 0x103bdb9e:
                    node = remote.get(registers, 'r4')
                    channel = remote.read(node + 1, 1)[0]
                    record['processing_dma_channel'] = channel
                    if channel < 16:
                        record['processing_dma_words'] = [hex(value) for value in struct.unpack(
                            '<13I', remote.read(0x20100400 + channel * 0x40, 52))]
                if pc == 0x103bd03a:
                    record['processing_controller'] = [hex(value) for value in struct.unpack(
                        '<17I', remote.read(0x20100000, 68))]
                    record['processing_dma'] = [dict(channel=channel, words=[hex(value) for value in struct.unpack(
                        '<13I', remote.read(0x20100400 + channel * 0x40, 52))]) for channel in range(16)]
                if pc in (0x103b4b1e, 0x103b4b26, 0x103b4b2e, 0x103b4b3e, 0x103b4b42):
                    task = remote.get(registers, 'r4')
                    record['processing_worker'] = processing_worker_snapshot(remote, task)
                    if pc == 0x103b4b3e:
                        record['processing_worker']['wait_flags'] = hex(remote.get(registers, 'r1'))
                    if pc == 0x103b4b42:
                        record['processing_worker']['returned_flags'] = hex(int.from_bytes(remote.read(
                            remote.get(registers, 'sp') + 4, 4), 'little'))
                if pc in CORE_WORKER_POINTS:
                    index = remote.get(registers, 'r5')
                    task = remote.get(registers, 'r0') if pc == 0x103b4e1e else 0xb1d52600 + index * 72
                    if task in (0xb1d52600, 0xb1d52648):
                        record['processing_core'] = processing_worker_snapshot(remote, task)
                        if pc == 0x103b4e1e:
                            record['processing_core']['activation'] = remote.get(registers, 'r1')
                        if pc == 0x103b4f26:
                            record['processing_core']['wait_flags'] = hex(remote.get(registers, 'r1'))
                        if pc == 0x103b4f2a:
                            record['processing_core']['returned_flags'] = hex(int.from_bytes(remote.read(
                                remote.get(registers, 'sp'), 4), 'little'))
                if pc == 0x10389b56:
                    pointer = remote.get(registers, 'r2')
                    values = struct.unpack('<80I', remote.read(pointer, 320))
                    record['processing_address_bindings'] = dict(address=hex(pointer),
                        bank_selector=remote.get(registers, 'r1'),
                        banks=[[hex(value) for value in values[index * 16:(index + 1) * 16]]
                               for index in range(4)], enabled=list(values[64:]))
                if pc == 0x10389b90:
                    pointer = remote.get(registers, 'r1')
                    data = remote.read(pointer, 20)
                    record['processing_port_configuration'] = dict(address=hex(pointer),
                        controls=list(data[:8]), word_8=hex(struct.unpack_from('<I', data, 8)[0]),
                        word_c=hex(struct.unpack_from('<I', data, 12)[0]),
                        halfword_10=struct.unpack_from('<H', data, 16)[0],
                        byte_12=data[18], port=data[19])
                if pc == 0x103e1dea:
                    packet = remote.get(registers, 'r1')
                    record['display_packet'] = dict(address=hex(packet),
                        words={hex(offset): hex(int.from_bytes(remote.read(packet + offset, 4), 'little'))
                               for offset in (0, 4, 8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20,
                                              0xdc, 0xe0, 0xe4, 0xe8, 0xec, 0xf0, 0xf4, 0xf8)})
                    if (shutter_on_preview or shutter_on_ready or capture_submit_on_ready) and not preview_press_sent:
                        paths = ['/machine/unattached/' + name for name in machine.config_names]
                        path = next(path for path in paths if machine.qmp.command(
                            'qom-get', dict(path=path, property='master-role')))
                        completed = machine.qmp.command('qom-get',
                            dict(path=path, property='processing-dma-count'))
                        gate = int.from_bytes(remote.read(0xb1821e84, 4), 'little')
                        if completed and (not (shutter_on_ready or capture_submit_on_ready) or gate == 0):
                            if image_work_events and not image_work_armed:
                                for address, label in (IMAGE_WORK_POINTS | IMAGE_WORK_WAIT_POINTS).items():
                                    remote.breakpoint(address)
                                    armed[address] = label
                                image_work_armed = True
                                record['image_work_observation_after_processing_frames'] = completed
                            if body_state_events and not body_status_armed:
                                for address, label in BODY_STATUS_POINTS.items():
                                    remote.breakpoint(address)
                                    armed[address] = label
                                body_status_armed = True
                                record['body_status_observation_after_processing_frames'] = completed
                            if body_capture_events and not body_capture_armed:
                                for address, label in BODY_CAPTURE_POINTS.items():
                                    remote.breakpoint(address)
                                    armed[address] = label
                                body_capture_armed = True
                                record['body_capture_observation_after_processing_frames'] = completed
                            if body_input_events and not body_input_armed:
                                for address, label in BODY_INPUT_POINTS.items():
                                    remote.breakpoint(address)
                                    armed[address] = label
                                body_input_armed = True
                                record['body_input_observation_after_processing_frames'] = completed
                            if body_compute_events and not body_compute_armed:
                                for address, label in BODY_COMPUTE_POINTS.items():
                                    remote.breakpoint(address)
                                    armed[address] = label
                                body_compute_armed = True
                                record['body_compute_observation_after_processing_frames'] = completed
                            if body_system_events and not body_system_armed:
                                for address, label in BODY_SYSTEM_POINTS.items():
                                    remote.breakpoint(address)
                                    armed[address] = label
                                body_system_armed = True
                                record['body_system_observation_after_processing_frames'] = completed
                            ticks = int.from_bytes(remote.read(0x04266008, 8), 'little')
                            if capture_submit_on_ready:
                                idle_preview_seen = True
                                blocked = capture_caller.blocking_resources() if capture_wait_idle else []
                                record['capture_pending_resources'] = blocked
                                if not blocked:
                                    capture_caller.trigger()
                                    preview_press_sent = True
                                    record['diagnostic_capture_after_processing_frames'] = completed
                                    record['release_gate_before_diagnostic_capture'] = gate
                            elif half_before_full and preview_half_tick is None:
                                machine.set_key(24, 0)
                                preview_half_tick = ticks
                                record['half_press_after_processing_frames'] = completed
                            elif not half_before_full or ticks - preview_half_tick >= before['counter_frequency'] // 2:
                                machine.set_key(25, 0)
                                preview_press_sent = True
                                preview_full_tick = ticks
                                click['press_ticks'] = ticks
                                record['shutter_after_processing_frames'] = completed
                                record['release_gate_before_press'] = gate
                                if half_before_full:
                                    record['half_press_counter_seconds'] = (
                                        ticks - preview_half_tick) / before['counter_frequency']
                if playback or returning or reconfigure or shutter_on_preview or shutter_on_ready or capture_submit_on_ready:
                    record['capture_state'] = list(remote.read(0xb23f6a80, 2))
                    record['driver_state'] = remote.read(0xb1868af1, 1)[0]
                    record['driver_pending_state'] = remote.read(0xb1868afa, 1)[0]
                    record['driver_mode'] = remote.read(0xb1868af7, 1)[0]
                    record['counter_ticks'] = int.from_bytes(remote.read(0x04266008, 8), 'little')
                    if returning:
                        hits[pc] = hits.get(pc, 0) + 1
                        repeat = hits[pc] < 8
                        record['application_index'] = remote.read(0xb1811e50, 1)[0]
                    if pc == 0x10321a4c:
                        callback_hits += int(keep)
                        record['notification'] = hex(remote.get(registers, 'r0'))
                        if remote.get(registers, 'r0') == 0x041a000d:
                            record['result_bytes'] = list(remote.read(
                                remote.get(registers, 'r1'), 2))
                        if not capture_caller:
                            repeat = callback_hits < 8
                    if pc == 0x10397260:
                        record['stop_command'] = list(struct.unpack('<4I', remote.read(0xb23ed1a0, 16)))
                    if pc in (0x1026c37c, 0x1026c174, 0x1026c220, 0x1026c25e):
                        record['failure_details'] = list(struct.unpack(
                            '<3I', remote.read(remote.get(registers, 'r1'), 12)))
                    if local_stop_events and pc in (0x102d987c, 0x102d98c4, 0x102d9902):
                        bit = {0x102d987c: 7, 0x102d98c4: 10, 0x102d9902: 18}[pc]
                        mask = int.from_bytes(remote.read(0x20060040, 4), 'little')
                        record['external_sync_event'] = dict(bank=2, bit=bit, mask=hex(mask))
                        require(mask & (1 << bit), 'Requested synchronization event is masked')
                        for level in (0, 1, 0):
                            machine._qtest(f'set_irq_in /machine/unattached/{machine.config_names[0]} '
                                           f'sync-event {11 + bit} {level}')
                    if returning and gpio_handshake_events and pc in (
                            0x10395a88, 0x102422c2, 0x102422ea):
                        mask = int.from_bytes(remote.read(0x0426f000, 4), 'little')
                        polarity = int.from_bytes(remote.read(0x0426f014, 4), 'little')
                        record['external_gpio_event'] = dict(
                            input=0, resource=84, intid=65, mask=hex(mask),
                            polarity=hex(polarity), injected=not bool(mask & 1))
                        if not mask & 1:
                            for level in (0, 1, 0):
                                machine._qtest(f'set_irq_in /machine/unattached/{machine.config_names[0]} '
                                               f'gpio-input 0 {level}')
                if frame_notify and not (capture_focus and pc in CAPTURE_INPUT_POINTS) and pc in (0x10238d4a, 0x10238c40, 0x1023c960, 0x1023beec,
                                           0x1022e2e0, 0x1022e0ae, 0x1022e154, 0x1022e1aa,
                                           0x10321d80, 0x10321d94, 0x10321dbe, 0x10321e22, 0x10321e24,
                                           0x1032206e, 0x10322126, 0x10322250, 0x10325304,
                                           0x10233570, 0x10398206, 0x10233b9c, 0x10232154,
                                           0x102313ea, 0x10231472, 0x10231486, 0x102314e6,
                                           0x102315c2, 0x10326676,
                                           0x102315c4, 0x103279c0, 0x10327c88, 0x10319d88,
                                           0x103191c4, 0x103231b2,
                                           0x1032a792):
                    hits[pc] = hits.get(pc, 0) + int(keep)
                    limit = 32 if capture_caller and pc in capture_caller.ui_points else 8
                    repeat = not keep or hits[pc] < limit
                    pointer = None
                    if pc == 0x1022e2e0:
                        code = remote.get(registers, 'r0')
                        record['notification'] = hex(code)
                        if code == 0x041a0002:
                            pointer = remote.get(registers, 'r1')
                            record['completed_object'] = hex(pointer)
                    elif pc in (0x1022e0ae, 0x1032a792, 0x10232154):
                        pointer = remote.get(registers, 'r0')
                    elif pc == 0x1023beec:
                        pointer = remote.get(registers, 'r1')
                    elif pc in (0x1022e154, 0x1022e1aa, 0x1032206e, 0x10322126,
                                0x10322250, 0x10325304, 0x10398206, 0x10233b9c):
                        pointer = remote.get(registers, 'r4')
                    elif pc in (0x10231472, 0x10231486, 0x102314e6, 0x102315c2, 0x102315c4):
                        pointer = remote.get(registers, 'r4')
                    elif pc == 0x10233570:
                        pointer = int.from_bytes(remote.read(remote.get(registers, 'r0'), 4), 'little')
                    elif pc == 0x10321d80:
                        packet = remote.get(registers, 'r4')
                        pointer = int.from_bytes(remote.read(packet + 8, 4), 'little')
                    elif pc in (0x10321d94, 0x10321dbe, 0x10321e22, 0x10321e24):
                        pointer = remote.get(registers, 'r5')
                    if pointer is not None and 0xb2c00000 <= pointer < 0xb5effe00:
                        record['context'] = dict(address=hex(pointer),
                            parameters=hex(int.from_bytes(remote.read(pointer + 0x144, 4), 'little')),
                            pending=hex(int.from_bytes(remote.read(pointer + 0x14c, 4), 'little')),
                            consumers=hex(remote.read(pointer + 0xc, 1)[0]),
                            output_fields={hex(offset): hex(int.from_bytes(remote.read(pointer + offset, 4), 'little'))
                                           for offset in (0x20, 0x30, 0x34, 0x38, 0x40, 0x68, 0x6c, 0x70)})
                        if pc in (0x1032206e, 0x10322126, 0x10322250, 0x10325304):
                            record['driver_header'] = list(remote.read(0xb1868af0, 0x30))
                    if pc == 0x10398206:
                        record['frame_parameters'] = [hex(value) for value in struct.unpack(
                            '<29I', remote.read(remote.get(registers, 'r0'), 0x74))]
                    if keep and pc in (0x102313ea, 0x10231472, 0x10231486, 0x102314e6,
                              0x102315c2, 0x102315c4, 0x103279c0, 0x10327c88, 0x10319d88,
                              0x10326676):
                        record['input_ready_fields'] = {hex(offset): hex(int.from_bytes(
                            remote.read(0xb1887d70 + offset, 4), 'little'))
                            for offset in (0, 0x40, 0x50, 0x54, 0x58)}
                        record['driver_header'] = list(remote.read(0xb1868af0, 0x30))
                    if keep and pc == 0x10319d88:
                        record['queue_words'] = [hex(value) for value in struct.unpack(
                            '<5I', remote.read(0xb23ede14, 20))]
                if pc == 0x1022aaae:
                    record['engine_release_gpio'] = engine_release_gpio_snapshot(remote, thread)
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < 16
                if pc == ACTION:
                    action = int.from_bytes(remote.read(
                        remote.get(registers, 'sp') + 0xc, 4), 'little')
                    full = bool(remote.get(registers, 'r5') & 0x40000000)
                    record.update(action=hex(action), full_press=full)
                    if action in (0x13, 0x14):
                        record['controller_release_irq'] = controller_release_irq_snapshot(remote, thread)
                        record['engine_release_gpio'] = engine_release_gpio_snapshot(remote, thread)
                    repeat = action != 0x1a if playback else not (full and action == 0x14)
                    if not repeat:
                        record['switch_words'] = [hex(x) for x in struct.unpack(
                            '<III', remote.read(0xb25eaeac, 12))]
                        following = {} if playback else dict(AFTER_ACTION)
                        if body_state_events:
                            following.update(BODY_STATE_POINTS)
                        elif body_capture_events:
                            following.update(BODY_CAPTURE_CONFIGURATION_POINTS)
                        elif application_only and not (image_work_events or body_capture_events or
                                                        body_input_events or body_compute_events or body_system_events):
                            following.update(BODY_CONFIGURATION_POINTS)
                        for address, label in following.items():
                            if address not in armed:
                                remote.breakpoint(address)
                            armed[address] = label
                    if shutter_click:
                        hits[pc] = hits.get(pc, 0) + 1
                        repeat = hits[pc] < 64
                if pc in IMAGE_WORK_POINTS or pc in (0x103d1132, 0x103ce528):
                    name = ('r7' if pc == 0x103d1132 else 'r6' if pc == 0x103ce528
                            else 'r4' if pc in (0x103cc8e8, 0x103cc960)
                            else 'r1' if pc in (0x103d0c3a, 0x103ce236) else 'r0')
                    pointer = remote.get(registers, name)
                    if capture_focus and pc in CAPTURE_WORK_POINTS:
                        keep = keep and pointer in capture_work_requests
                    record['image_work_request'] = hex(pointer)
                    if 0xb2c00000 <= pointer <= 0xb5effd30:
                        def word(address):
                            return int.from_bytes(remote.read(address, 4), 'little')
                        parameters, stages = word(pointer), word(pointer + 4)
                        record['image_work'] = dict(parameters=hex(parameters), stages=hex(stages),
                            completion=hex(word(pointer + 0x2c8)),
                            stage_states=[remote.read(pointer + 0x8c + index * 8, 1)[0]
                                          for index in range(11)],
                            stage_indices=[word(pointer + 0x90 + index * 8) for index in range(11)])
                        if 0xb1800000 <= stages <= 0xb5effd6c:
                            values = struct.unpack('<165I', remote.read(stages, 660))
                            record['image_work']['active_stage_entries'] = [
                                [hex(value) for value in values[index * 15:(index + 1) * 15] if value]
                                for index in range(11)]
                        if 0xb2c00000 <= parameters <= 0xb5efc1bc:
                            record['image_work'].update(owner=hex(word(parameters + 0xc)),
                                scheduler=hex(word(parameters + 8)))
                            if word(pointer + 0x2c8) == 0x103ce237:
                                if parameters <= 0xb5efb42b:
                                    record['image_work'].update(queue_flags=hex(word(parameters + 0x74)),
                                        control_flags=remote.read(parameters + 0x4bd4, 1)[0])
                            else:
                                record['image_work'].update(queue_flags=hex(word(parameters + 0x6c)),
                                    busy=remote.read(parameters + 0x3e30, 1)[0])
                    if pc == 0x102456fc:
                        record['worker_stage'] = remote.get(registers, 'r1')
                    if capture_focus and pc in (0x103d0c3a, 0x103ce236):
                        capture_work_requests.discard(pointer)
                        if 'image_work' in record:
                            capture_work_parameters.pop(int(record['image_work']['parameters'], 0), None)
                    if not (capture_focus and pc in CAPTURE_INPUT_POINTS):
                        hits[pc] = hits.get(pc, 0) + int(keep)
                        repeat = not keep or hits[pc] < 8
                if capture_focus and pc in CAPTURE_WORK_WAIT_POINTS:
                    parameters = remote.get(registers, 'r6') - (0x24 if pc in (0x102e6518, 0x102e651c) else 0)
                    keep = keep and parameters in capture_work_parameters
                    if keep:
                        stack = remote.get(registers, 'sp')
                        record['capture_work_wait'] = dict(parameters=hex(parameters),
                            request=hex(capture_work_parameters[parameters]))
                        if pc in (0x102e6518, 0x10269e02):
                            record['capture_work_wait'].update(object=hex(remote.get(registers, 'r0')),
                                mask=hex(remote.get(registers, 'r1')),
                                timeout=remote.get(registers, 'r3'))
                        else:
                            record['capture_work_wait']['result'] = remote.get(registers, 'r0')
                        flags = stack if pc in (0x102e6518, 0x102e651c) else stack + 0x434
                        record['capture_work_wait']['returned_or_seeded_flags'] = hex(int.from_bytes(
                            remote.read(flags, 4), 'little'))
                        if pc in (0x10269e02, 0x10269e06):
                            record['capture_work_wait'].update(
                                queried_count=int.from_bytes(remote.read(stack + 0x430, 4), 'little'),
                                completed_count=int.from_bytes(remote.read(0xb18648f0, 4), 'little'))
                    hits[pc] = hits.get(pc, 0) + int(keep)
                    repeat = not keep or hits[pc] < 8
                if pc in IMAGE_WORK_WAIT_POINTS:
                    if pc in (0x1026981c, 0x10269820, 0x102698a0, 0x102698a4):
                        record['returned_or_seeded_flags'] = hex(int.from_bytes(
                            remote.read(remote.get(registers, 'sp') + 0x430, 4), 'little'))
                        record['parameters'] = hex(remote.get(registers, 'r4'))
                    if pc == 0x10262e40:
                        record['image_work_counters'] = {hex(offset): hex(int.from_bytes(
                            remote.read(0xb18648b4 + offset, 4), 'little'))
                            for offset in range(0x24, 0x50, 4)}
                    if pc in (0x10268c2a, 0x10268c2e):
                        record['returned_or_seeded_flags'] = hex(int.from_bytes(
                            remote.read(remote.get(registers, 'sp') + 8, 4), 'little'))
                        record['parameters'] = hex(remote.get(registers, 'r4'))
                    if pc in (0x1026830e, 0x10268312):
                        record['returned_or_seeded_flags'] = hex(int.from_bytes(
                            remote.read(remote.get(registers, 'sp'), 4), 'little'))
                        record['parameters'] = hex(remote.get(registers, 'r4'))
                    if pc == 0x10266476:
                        pointer = remote.get(registers, 'r0')
                        if 0xb2c00000 <= pointer <= 0xb5efffe4:
                            record['dependent_event'] = [hex(value) for value in struct.unpack(
                                '<3I', remote.read(pointer + 0x10, 12))]
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < 8
                if pc in BODY_CONFIGURATION_POINTS:
                    pointer = remote.get(registers, 'r0') if pc in (0x10635cf6, 0x104847c2) else None
                    if pointer is not None and 0xb1800000 <= pointer <= 0xb5efff38:
                        record['configuration_list'] = dict(address=hex(pointer),
                            callback=hex(remote.get(registers, 'r1')),
                            queue=[hex(value) for value in struct.unpack('<5I', remote.read(pointer + 0x9c, 20))])
                    if pc in (0x10484800, 0x10484802, 0x1048480a):
                        pointer = remote.get(registers, 'r4')
                        if 0xb1800000 <= pointer <= 0xb5efffb0:
                            record['configuration_node'] = dict(address=hex(pointer),
                                fields={hex(offset): hex(int.from_bytes(remote.read(pointer + offset, 4), 'little'))
                                        for offset in (0, 4, 0x10, 0x14, 0x28, 0x2c,
                                                       0x30, 0x34, 0x40, 0x44, 0x48, 0x4c)})
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < (512 if body_capture_events and pc == 0x10484800 else 64)
                if body_capture_events and pc == 0x1048481e:
                    record['configuration_result'] = remote.get(registers, 'r6')
                    record['visited_nodes'] = remote.get(registers, 'r5')
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < 64
                if body_state_events and pc in BODY_STATE_POINTS:
                    if pc == 0x104e6cb4:
                        record['state_inputs'] = {
                            'context_bytes': {hex(offset): remote.read(0xb202be70 + offset, 1)[0]
                                              for offset in (0, 8, 0x1a7, 0x214)},
                            'context_pair': list(remote.read(0xb202c1fc, 2)),
                            'state_bytes': list(remote.read(0xb181b46b, 2)),
                        }
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < 8
                if body_state_events and pc in BODY_STATUS_POINTS:
                    record['body_status'] = {
                        'state_bytes': list(remote.read(0xb25d8974, 3)),
                        'property180b': hex(int.from_bytes(remote.read(0xb2551b54, 4), 'little')),
                    }
                    if pc == 0x106d1ed2:
                        record['body_status'].update(new_state=remote.get(registers, 'r4'),
                                                    notify=remote.get(registers, 'r5'))
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < 32
                if body_capture_events and pc in BODY_CAPTURE_POINTS:
                    operation = remote.get(registers, 'r0')
                    if pc == 0x1022827c and operation in (7, 9):
                        key = str(operation)
                        body_periodic_operations[key] = body_periodic_operations.get(key, 0) + 1
                        keep = False
                        repeat = True
                    else:
                        if pc == 0x1022827c:
                            record['operation'] = operation
                            record['callback'] = hex(remote.get(registers, 'r1'))
                            if operation < 124:
                                record['existing_callback'] = hex(int.from_bytes(
                                    remote.read(0xb23f6fe4 + operation * 4, 4), 'little'))
                        hits[pc] = hits.get(pc, 0) + 1
                        repeat = hits[pc] < 32
                if body_input_events and pc in BODY_INPUT_POINTS:
                    body_input_samples[hex(pc)] = body_input_samples.get(hex(pc), 0) + 1
                    pointer = remote.get(registers, 'r0' if pc == 0x102a4794 else
                                         'sp' if pc == 0x1029ee9c else 'r4')
                    result = None if pc == 0x102a4794 else remote.get(registers, 'r0')
                    keep = keep and (pc != 0x1029ee9c or result != 2)
                    if keep and 0xb0000000 <= pointer <= 0xb5efffe8:
                        words = struct.unpack('<6I', remote.read(pointer, 24))
                        # Compare only release contacts, retaining all six original words.
                        signature = tuple(value & 0xc0000000 for value in words[1:])
                        keep = body_input_seen.get(pc) != signature
                        body_input_seen[pc] = signature
                        if keep:
                            record['body_input'] = dict(address=hex(pointer),
                                words={hex(index * 4): hex(value) for index, value in enumerate(words)},
                                result=result)
                    else:
                        keep = False
                    hits[pc] = hits.get(pc, 0) + int(keep)
                    repeat = hits[pc] < 32
                if body_compute_events and pc in BODY_COMPUTE_POINTS:
                    record['master_compute'] = master_compute_snapshot(remote)
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < 8
                if body_system_events and pc in BODY_SYSTEM_POINTS:
                    root = 0xb1818bd0
                    word = lambda address: int.from_bytes(remote.read(address, 4), 'little')
                    mode = word(root + 0x154)
                    record['body_system'] = dict(mode_object=hex(mode),
                        mode_bytes=list(remote.read(root + 0x158, 2)),
                        blocked=[hex(word(root + offset)) for offset in (0x320, 0x324, 0x328)],
                        pending=hex(word(root + 0x32c)))
                    if 0xb1800000 <= mode <= 0xb5effeb0:
                        record['body_system']['mode_fields'] = {
                            hex(offset): hex(word(mode + offset)) for offset in
                            (0, 0x3c, 0x44, 0x64, 0xa4, 0xa8, 0x108, 0x110,
                             0x114, 0x118, 0x11c, 0x120, 0x124, 0x128, 0x12c)}
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < 32
                if pc == 0x104e6c28:
                    record['release_gate'] = remote.get(registers, 'r0')
                    record['action'] = hex(remote.get(registers, 'r6'))
                if pc in (0x104e1714, 0x104e1910):
                    record['configuration_saved_registers'] = {
                        name: hex(remote.get(registers, name)) for name in ('r8', 'r9', 'r10', 'r11')}
                if pc in (0x10542064, 0x10542070, 0x10542076, 0x10542368,
                          0x1054238a, 0x10542394):
                    record['action_saved_registers'] = {
                        name: hex(remote.get(registers, name)) for name in ('r8', 'r9', 'r10', 'r11')}
                if capture_focus and capture_input_path is not None and pc in CAPTURE_INPUT_POINTS:
                    if pc in (0x10448496, 0x104484de, 0x104d7596, 0x10448e92, 0x10448e96):
                        keep = keep and capture_caller is not None and capture_caller.report['triggered']
                        if keep:
                            record['display_delivery'] = display_delivery_snapshot(remote.read)
                            if pc in (0x10448e92, 0x10448e96):
                                stack = remote.get(registers, 'sp')
                                record['display_delivery'].update(
                                    reset_mode=remote.get(registers, 'r6'),
                                    reset_caller=hex(int.from_bytes(remote.read(stack + 0x9c, 4), 'little')))
                            elif pc == 0x104d7596:
                                record['display_delivery'].update(actual_mode=remote.get(registers, 'r0'),
                                    required_mode=remote.get(registers, 'r4'))
                            else:
                                packet = remote.get(registers, 'r8' if pc == 0x10448496 else 'r4')
                                offset = 0xf4 if pc == 0x10448496 else 0xf0
                                if 0xb1800000 <= packet <= 0xb5effb48:
                                    record['display_delivery']['submitted_background'] = hex(int.from_bytes(
                                        remote.read(packet + offset, 4), 'little'))
                    if pc == 0x103bde3e:
                        status = remote.get(registers, 'r0')
                        keep = keep and bool(capture_work_requests) and bool(status & 0x610061)
                        if keep:
                            record['output_status_dispatch'] = dict(status_1c=hex(status),
                                status_20=hex(remote.get(registers, 'r1')),
                                forwarding_mask=hex(int.from_bytes(remote.read(0xb1809554, 4), 'little')),
                                subscriber=hex(int.from_bytes(remote.read(0xb1809550, 4), 'little')),
                                hardware_mask_10=hex(int.from_bytes(remote.read(0x20100010, 4), 'little')))
                    if pc == 0x10262e64:
                        keep = keep and bool(capture_work_requests)
                        if keep:
                            record['processing_result_event'] = dict(
                                mask=hex(remote.get(registers, 'r5')),
                                count_before=int.from_bytes(remote.read(0xb18648f0, 4), 'little'))
                    if pc in (0x103d1132, 0x103ce528):
                        keep = keep and record['capture_state'][0] >= 8
                        if keep:
                            request = remote.get(registers, 'r7' if pc == 0x103d1132 else 'r6')
                            if pc == 0x103d1132:
                                record['work_registration_result'] = remote.get(registers, 'r0')
                            record['work_origin'] = 'staged-context' if pc == 0x103d1132 else 'still-input'
                            capture_work_requests.add(request)
                            if 'image_work' in record:
                                capture_work_parameters[int(record['image_work']['parameters'], 0)] = request
                            for address, label in (CAPTURE_WORK_POINTS | CAPTURE_WORK_WAIT_POINTS).items():
                                if address not in armed and hits.get(address, 0) < 8:
                                    armed[address] = label
                                    remote.breakpoint(address)
                    if pc in (0x102e4548, 0x102e455c, 0x102e4570, 0x102e4574):
                        keep = keep and record['capture_state'][0] >= 6
                        if keep:
                            packet = remote.get(registers, 'r11')
                            stack = remote.get(registers, 'sp')
                            record['image_control_wait'] = dict(packet=hex(packet),
                                saved_flags=hex(int.from_bytes(remote.read(stack + 4, 4), 'little')),
                                command_kind=int.from_bytes(remote.read(stack + 8, 4), 'little'))
                            if pc in (0x102e4548, 0x102e4570):
                                record['image_control_wait'].update(object=hex(remote.get(registers, 'r0')),
                                    mask=hex(remote.get(registers, 'r1')))
                            else:
                                record['image_control_wait']['result'] = remote.get(registers, 'r0')
                            if 0xb1800000 <= packet <= 0xb5efffe4:
                                record['image_control_wait']['packet_fields'] = {
                                    hex(offset): hex(int.from_bytes(remote.read(packet + offset, 4), 'little'))
                                    for offset in (0xc, 0x10, 0x14, 0x18)}
                    if pc == 0x10369fc4:
                        keep = keep and record['capture_state'][0] >= 6
                        if keep:
                            pointer = remote.get(registers, 'r0')
                            if 0xb1800000 <= pointer <= 0xb5effffb:
                                record['image_stop_bank'] = remote.read(pointer + 4, 1)[0]
                    if pc in (0x103d0df0, 0x103d0e00, 0x103d0eae):
                        keep = keep and record['capture_state'][0] >= 8
                    if pc == 0x103cdb26:
                        keep = keep and remote.get(registers, 'r0') == 0x041b0042
                    if pc in (0x10264f5c, 0x10265120, 0x102639d6, 0x102642a4,
                              0x10263820, 0x102642c6):
                        keep = keep and record['capture_state'][0] >= 6
                    if keep and pc in (0x10263820, 0x102642c6):
                        record['release_wait'] = dict(result=remote.get(registers, 'r0'),
                            mask=hex(remote.get(registers, 'r5' if pc == 0x10263820 else 'r4')))
                    if keep and pc in (0x103d0df0, 0x103d0e00, 0x103d0eae,
                                       0x10264f5c, 0x10265120, 0x103cdb26,
                                       0x102639d6, 0x102642a4, 0x10263820, 0x102642c6):
                        record['processing_release'] = {
                            hex(offset): hex(int.from_bytes(remote.read(0xb1864834 + offset, 4), 'little'))
                            for offset in (0, 4, 8, 0xc, 0x10, 0x14, 0x1c, 0x20, 0x50, 0x54, 0x60)}
                        if pc in (0x10264f5c, 0x103d0df0):
                            record['processing_control_workers'] = [dict(
                                task=task_wait_snapshot(remote, address),
                                fields={hex(offset): hex(int.from_bytes(remote.read(address + offset, 4), 'little'))
                                        for offset in (0, 4, 8, 0xc, 0x10, 0x14, 0x18, 0x1c,
                                                       0x20, 0x24, 0x28, 0x2c, 0x14c, 0x150)})
                                for address in (0xb1d52938, 0xb1d52a8c)]
                    if pc in (0x103d0df0, 0x103d0e00, 0x103d0eae):
                        if keep:
                            pointer = remote.get(registers, 'r4')
                            record['work_mode'] = dict(context=hex(pointer),
                                manager_header=list(remote.read(0xb1864d48, 8)),
                                parameter_backend_header=list(remote.read(0xb1866d4c, 8)),
                                output_flags=hex(int.from_bytes(remote.read(0xb23ccd94, 4), 'little')))
                            if 0xb1800000 <= pointer <= 0xb5effff2:
                                record['work_mode']['context_kind'] = remote.read(pointer + 0xd, 1)[0]
                    if pc in (0x10326608, 0x10326620, 0x10326624):
                        context = int.from_bytes(remote.read(remote.get(registers, 'r5') + 0x14, 4), 'little')
                        parameters = remote.get(registers, 'r6')
                        record['staged_work'] = dict(context=hex(context), parameters=hex(parameters),
                            driver_2e=remote.read(0xb1868b1e, 1)[0])
                        if 0xb1800000 <= parameters <= 0xb5effb2b:
                            record['staged_work']['fields'] = {
                                hex(offset): hex(int.from_bytes(remote.read(parameters + offset, size), 'little'))
                                for offset, size in ((0, 1), (1, 1), (4, 4), (8, 4), (0xc, 1),
                                                     (0x10, 4), (0x14, 4), (0x18, 4), (0x20, 4),
                                                     (0x38, 4), (0xac, 1), (0x107, 1), (0x4d4, 1))}
                        if 0xb1800000 <= parameters <= 0xb5efd232:
                            record['staged_work']['parameter_2dcd'] = remote.read(parameters + 0x2dcd, 1)[0]
                        if pc == 0x10326624:
                            record['staged_work']['submit_result'] = hex(remote.get(registers, 'r0'))
                    if pc in (0x10321d80, 0x10321d94, 0x10321dbe, 0x10325304,
                              0x103262e8, 0x10326546):
                        # Preview notifications otherwise consume the hit limit before release.
                        keep = keep and (pc in (0x10325304, 0x103262e8, 0x10326546) or
                                         record['capture_state'][0] >= 6)
                        if keep:
                            name = ('r0' if pc == 0x10326546 else 'r4' if pc in
                                    (0x10325304, 0x103262e8) else 'r5')
                            pointer = remote.get(registers, name)
                            if pc == 0x10321d80:
                                packet = remote.get(registers, 'r4')
                                pointer = int.from_bytes(remote.read(packet + 8, 4), 'little')
                            if 0xb1800000 <= pointer <= 0xb5effd8c:
                                record['image_context'] = dict(address=hex(pointer),
                                    kind=remote.read(pointer + 0xd, 1)[0],
                                    consumers=remote.read(pointer + 0xc, 1)[0],
                                    fields={hex(offset): hex(int.from_bytes(remote.read(pointer + offset, 4), 'little'))
                                            for offset in (0x10, 0x20, 0x40, 0x68, 0x144, 0x14c, 0x270)})
                            if pc in (0x10325304, 0x103262e8, 0x10326546):
                                parameters = remote.get(registers, 'r6')
                                record['pending_context_parameters'] = hex(parameters)
                                if 0xb1800000 <= parameters <= 0xb5efff53:
                                    record['context_parameter_ac'] = hex(remote.read(parameters + 0xac, 1)[0])
                                if 0xb1800000 <= parameters <= 0xb5efd232:
                                    record['context_parameter_2dcd'] = remote.read(parameters + 0x2dcd, 1)[0]
                                if pc == 0x10325304:
                                    record['context_creation_kind'] = hex(remote.get(registers, 'r8'))
                    if pc in (0x1026a312, 0x1026a448):
                        descriptor = remote.get(registers, 'r0' if pc == 0x1026a312 else 'r6')
                        if 0xb1800000 <= descriptor <= 0xb5efff88:
                            context = int.from_bytes(remote.read(descriptor + 0xc, 4), 'little')
                            record['jpeg_worker'] = dict(descriptor=hex(descriptor), context=hex(context),
                                second_path=int.from_bytes(remote.read(descriptor + 4, 4), 'little'),
                                descriptor_74=remote.read(descriptor + 0x74, 1)[0])
                            if 0xb1800000 <= context <= 0xb5effd8c:
                                parameters = int.from_bytes(remote.read(context + 0x144, 4), 'little')
                                record['jpeg_worker'].update(kind=remote.read(context + 0xd, 1)[0],
                                    context_10=hex(int.from_bytes(remote.read(context + 0x10, 4), 'little')),
                                    context_270=hex(int.from_bytes(remote.read(context + 0x270, 4), 'little')),
                                    parameters=hex(parameters))
                                if 0xb1800000 <= parameters <= 0xb5efe940:
                                    record['jpeg_worker'].update(parameter_ac=hex(remote.read(parameters + 0xac, 1)[0]),
                                        parameter_16bc=hex(int.from_bytes(remote.read(parameters + 0x16bc, 4), 'little')))
                        if pc == 0x1026a448:
                            record['jpeg_output_allocation'] = hex(remote.get(registers, 'r0'))
                    if pc in (0x102b3362, 0x1026a4ba, 0x1026a5f8):
                        pointer = remote.get(registers, 'r0')
                        if 0xb1800000 <= pointer <= 0xb5efffd0:
                            record['jpeg_job_request'] = dict(address=hex(pointer),
                                fields={hex(offset): hex(int.from_bytes(remote.read(pointer + offset, 4), 'little'))
                                        for offset in (0, 4, 8, 0xc, 0x28, 0x2c)})
                    if pc in (0x1022ff42, 0x10230052):
                        record['tail_parameters'] = input_tail_parameter_snapshot(
                            remote, remote.get(registers, 'r5'))
                    if pc in (0x1032ac52, 0x1032ac9a):
                        keep = keep and capture_caller is not None and capture_caller.report['triggered']
                        if keep:
                            record['clone_mode'] = remote.get(registers, 'r0' if pc == 0x1032ac52 else 'r6')
                            record['clone_destination'] = input_tail_parameter_snapshot(
                                remote, remote.get(registers, 'r3' if pc == 0x1032ac52 else 'r4'))
                            if pc == 0x1032ac52:
                                record['clone_source'] = input_tail_parameter_snapshot(
                                    remote, remote.get(registers, 'r2'))
                    if pc == 0x1031a690:
                        keep = keep and capture_caller is not None and capture_caller.report['triggered']
                        if keep:
                            record['copy_source'] = input_tail_parameter_snapshot(
                                remote, remote.get(registers, 'r0'))
                            record['copy_destination'] = hex(remote.get(registers, 'r2'))
                            record['copy_nested_destination'] = hex(remote.get(registers, 'r3'))
                    if pc == 0x1031a638:
                        keep = keep and capture_caller is not None and capture_caller.report['triggered']
                        if keep:
                            record['initialized_parameter'] = hex(remote.get(registers, 'r1'))
                            record['initialized_nested'] = hex(remote.get(registers, 'r0'))
                    if pc == 0x10360468:
                        request, config = (remote.get(registers, name) for name in ('r0', 'r1'))
                        record['tail_configuration'] = dict(request=hex(request), config=hex(config))
                        if 0xb1800000 <= request <= 0xb5efff4f:
                            record['tail_configuration']['request_fields'] = {
                                hex(offset): hex(int.from_bytes(remote.read(request + offset, size), 'little'))
                                for offset, size in ((8, 1), (0x18, 4), (0x1c, 4), (0xb0, 1))}
                        if 0xb1800000 <= config <= 0xb5effea6:
                            record['tail_configuration']['config_fields'] = {
                                hex(offset): hex(int.from_bytes(remote.read(config + offset, size), 'little'))
                                for offset, size in ((0x44, 1), (0x48, 1), (0x148, 1),
                                                     (0x14c, 1), (0x150, 1), (0x154, 4), (0x158, 2))}
                        record['tail_configuration']['destination'] = hex(int.from_bytes(
                            remote.read(remote.get(registers, 'sp'), 4), 'little'))
                        record['effective_format_property_161a'] = hex(int.from_bytes(
                            remote.read(0xb25517d0, 4), 'little'))
                    if pc == 0x103eb2e4:
                        record['capture_request_variant_slots'] = capture_request_variant_slots_snapshot(remote)
                        record['transport_completion_callback'] = hex(int.from_bytes(
                            remote.read(0xb188b8dc, 4), 'little'))
                    if pc in (0x10326eee, 0x10326ff0, 0x1032729a):
                        record['metadata_condition_word'] = hex(int.from_bytes(
                            remote.read(0xb1868ca4, 4), 'little'))
                        pointer = int.from_bytes(remote.read(remote.get(registers, 'r5') + 0x20, 4), 'little')
                        record['metadata_parameters'] = input_tail_parameter_snapshot(remote, pointer)
                        if pc == 0x1032729a:
                            record['stage_descriptor'] = hex(remote.get(registers, 'r0'))
                    if pc == 0x103ce51e:
                        packet, length = remote.get(registers, 'r3'), remote.get(registers, 'r2')
                        if length == 20 and 0xb1800000 <= packet <= 0xb5efffec:
                            record['still_peer_request_words'] = [hex(value) for value in
                                struct.unpack('<5I', remote.read(packet, 20))]
                    if pc in (0x1031e83e, 0x1031e602, 0x1031e778, 0x1031e77e,
                              0x1031e782, 0x1031e80a, 0x103ce6ac, 0x103ce318,
                              0x103ce434, 0x103ce574):
                        keep = keep and record['capture_state'][0] >= 6
                        if keep:
                            if pc == 0x1031e83e:
                                pointer = int.from_bytes(remote.read(0xb23f0468, 4), 'little')
                            elif pc in (0x1031e602, 0x1031e782, 0x1031e80a):
                                stack = remote.get(registers, 'sp')
                                pointer = int.from_bytes(remote.read(stack + 4, 4), 'little')
                                record['selection_auxiliary'] = int.from_bytes(remote.read(stack + 8, 4), 'little')
                            elif pc in (0x103ce434, 0x103ce574):
                                pointer = remote.get(registers, 'r4')
                                record['still_request'] = hex(remote.get(registers, 'r6'))
                                record['still_parameters'] = hex(remote.get(registers, 'r5'))
                            else:
                                pointer = remote.get(registers, 'r0')
                            record['still_input'] = still_input_snapshot(remote, pointer)
                            record['still_input_queues'] = still_queue_snapshot(remote)
                    if pc == 0x103604ca:
                        record['tail_configuration_result'] = dict(
                            destination=hex(remote.get(registers, 'r4')),
                            nested_2844=hex(remote.get(registers, 'r5')),
                            nested_2848=hex(remote.get(registers, 'r0')),
                            pending_store=True)
                    if pc in (0x1020aafc, 0x1020ab00, 0x1020a830, 0x1020a834):
                        keep = keep and bool(remote.get(registers, 'r1') & 0x600)
                        if keep:
                            record['input_irq_masks'] = [hex(int.from_bytes(
                                remote.read(0x20068200 + bank * 32, 4), 'little')) for bank in range(8)]
                    record['input_source'] = {name: machine.qmp.command('qom-get',
                        dict(path=capture_input_path, property=property_name)) for name, property_name in
                        (('running_mask', 'input-running'), ('frame_ticks', 'frame-sync-count'),
                         ('primary_frames', 'primary-input-dma-count'))}
                    if pc == 0x1026a312:
                        keep = keep and (record['capture_state'][0] >= 6 or
                                         record['input_source']['primary_frames'] > 0)
                    if pc == 0x103b9848:
                        keep = keep and remote.get(registers, 'r0') == 0x04100074
                        pointer = remote.get(registers, 'r1')
                        if keep and 0xb1800000 <= pointer <= 0xb5effffc:
                            record['release_count_payload'] = int.from_bytes(remote.read(pointer, 4), 'little')
                    if pc == 0x1022e2e0:
                        keep = keep and remote.get(registers, 'r0') in (
                            0x041a0001, 0x041a0004, 0x04200005)
                    if pc in (0x1031eabe, 0x1031ead8, 0x1031cb20, 0x1031cb3a, 0x1032ae3c):
                        keep = keep and record['capture_state'][0] >= 7
                        if keep:
                            record['driver_input_flags'] = hex(int.from_bytes(
                                remote.read(0xb1868ca0, 4), 'little'))
                            record['driver_stop_flags'] = hex(int.from_bytes(
                                remote.read(0xb1868cf0, 4), 'little'))
                    if pc in (0x10328d36, 0x10323b44, 0x10321224, 0x10320e72,
                              0x10395dae, 0x10395cf4, 0x10395da4, 0x1022e802,
                              0x10327caa, 0x10326e86):
                        record['processing_header'] = list(remote.read(0xb1868310, 16))
                        record['processing_ready_callback'] = hex(int.from_bytes(
                            remote.read(0xb18683e4, 4), 'little'))
                    if pc == 0x1026ec26:
                        record['delegate_ready_mode'] = remote.read(0xb186851c, 1)[0]
                        record['delegate_ready_callback'] = hex(int.from_bytes(
                            remote.read(0xb1868530, 4), 'little'))
                    if pc == 0x10394762:
                        code = remote.get(registers, 'r0')
                        keep = keep and (0x03030001 <= code <= 0x03030005 or code == 0x0420010b)
                    if pc == 0x10394d06:
                        code = remote.get(registers, 'r0')
                        keep = keep and code in (0x04200185, 0x03030001, 0x03030002)
                    if pc == 0x1026d16e:
                        keep = keep and 0x04200281 <= remote.get(registers, 'r0') <= 0x04200288
                    if pc == 0x102dc83c:
                        keep = keep and bool(remote.get(registers, 'r1') & 0x18)
                    if pc == 0x102dc808:
                        keep = keep and bool(remote.get(registers, 'r1') & 0x30)
                    if pc == 0x10297710:
                        keep = keep and remote.get(registers, 'r0') in (8, 16)
                    if keep and pc in (0x10394710, 0x10395a70, 0x10394d06, 0x10397260,
                              0x1024229c, 0x102422c4, 0x102422ec, 0x10242124):
                        record['handshake'] = dict(
                            mode=remote.read(0xb18a7920, 1)[0],
                            timer_active=int.from_bytes(remote.read(0xb18a7924, 4), 'little'),
                            processing_active=int.from_bytes(remote.read(0xb1868334, 4), 'little'),
                            processing_parameters=list(remote.read(0xb23ed1a0, 4)),
                            device_qualifiers=list(remote.read(0xb23ecdd0, 3)),
                            processing_qualifiers=[remote.read(0xb1868315, 1)[0],
                                                   remote.read(0xb1868322, 1)[0]])
                    if keep and pc in (0x1026d16e, 0x102e9482, 0x102e958a,
                                      0x102e94fa, 0x102eb93e, 0x102eb778,
                                      0x102e8630, 0x102e8684, 0x102dc83c, 0x102dc808,
                                      0x10297710, 0x102e9b08, 0x102e9af6):
                        record['sampling_stage'] = dict(
                            header=list(remote.read(0xb1868628, 0x24)),
                            words=[hex(x) for x in struct.unpack('<20I', remote.read(0xb1868670, 80))],
                            delegate_header=list(remote.read(0xb1868510, 0x20)),
                            counter_context=list(remote.read(0xb1868880, 0x48)))
                        if pc == 0x10297710:
                            pointer = remote.get(registers, 'r1')
                            if 0xb1800000 <= pointer <= 0xb5efffd0:
                                record['sampling_output_parameters'] = [hex(x) for x in
                                    struct.unpack('<12I', remote.read(pointer, 48))]
                        record['sampling_output_control'] = [hex(x) for x in
                            struct.unpack('<10I', remote.read(0x20060000, 40))]
                    if pc in (0x1024220a, 0x102421aa):
                        record['adapter_dispatch'] = [hex(value) for value in
                            struct.unpack('<2I', remote.read(0xb18a7930, 8))]
                        pointer = remote.get(registers, 'r0')
                        if 0xb1800000 <= pointer <= 0xb5effff8:
                            record['adapter_request'] = list(struct.unpack('<2I', remote.read(pointer, 8)))
                    if pc in (0x103b93d0, 0x103b940a, 0x103b9538, 0x103b9184,
                              0x103ba1cc, 0x103ba1d0, 0x103ba29c, 0x103b9848, 0x103b9826):
                        record['release_control_header'] = list(remote.read(0xb186935c, 16))
                        record['release_control_words'] = {hex(offset): hex(int.from_bytes(
                            remote.read(0xb186935c + offset, 4), 'little')) for offset in
                            (0x34, 0x38, 0x3c, 0x40, 0x44, 0x48, 0x60, 0x68)}
                        if pc == 0x103ba1cc:
                            record['release_phase_request'] = [hex(value) for value in
                                struct.unpack('<2I', remote.read(remote.get(registers, 'r0'), 8))]
                        if pc == 0x103ba29c:
                            record['release_phase_result'] = remote.read(remote.get(registers, 'sp'), 1)[0]
                    if pc in (0x10238d4a, 0x10238d64, 0x10238d02):
                        keep = keep and record['input_source']['primary_frames'] > 0
                    if pc in (0x1023beec, 0x103cc8e8):
                        keep = keep and record['capture_state'][0] >= 7
                    if keep and pc in (0x10238d64, 0x10238d02, 0x1023c6ec, 0x1023beec):
                        record['input_pipeline'] = dict(
                            flags=hex(int.from_bytes(remote.read(0xb26b38cc, 4), 'little')),
                            queues=[int.from_bytes(remote.read(0xb26b392c + index * 32, 4), 'little')
                                    for index in range(4)],
                            fourth_object=hex(remote.get(registers, 'r8')))
                    if pc == 0x1023938c:
                        pointer = remote.get(registers, 'r1')
                        if 0xb1800000 <= pointer <= 0xb5efffe0:
                            record['input_cause_words'] = [hex(value) for value in
                                struct.unpack('<8I', remote.read(pointer, 32))]
                    hits[pc] = hits.get(pc, 0) + int(keep)
                    repeat = not keep or hits[pc] < (32 if pc in (
                        0x1031a638, 0x1031a690, 0x1032ac52, 0x1032ac9a,
                        0x10360468, 0x103604ca, 0x103eb2e4,
                        0x10325304, 0x103262e8, 0x10326546, 0x1026a312) else 8)
                if keep:
                    records.append(record)
                if mode1_frame_events and pc == 0x1023c5dc and len(mode1_events) == 1:
                    latch = int.from_bytes(remote.read(0xb26b38dc, 4), 'little')
                    record['mode1_output_latch'] = latch
                    record['mode1_output_controls'] = {hex(address): hex(int.from_bytes(
                        remote.read(address, 4), 'little')) for address in
                        (0x20068100, 0x20068104, 0x2006a53c, 0x2006a548,
                         0x2006a550, 0x2006a560, 0x2006a580)}
                    if latch == 1:
                        pulse_mode1()
                if pc in RECONFIGURE_POINTS and (reconfigure or pc == 0x103e1dea):
                    hits[pc] = hits.get(pc, 0) + 1
                    repeat = hits[pc] < (64 if pc == 0x1022827c or
                                        (shutter_on_ready or capture_submit_on_ready) and not preview_press_sent and
                                        pc == 0x103e1dea else 32 if pc == 0x103bded0 or
                                        half_before_full and pc == 0x103e1dea else 8)
            remote.breakpoint(pc, False)
            if repeat:
                remote.sock.settimeout(15)
                remote.command(f'vCont;s:{thread:x}')
                remote.breakpoint(pc)
            else:
                del armed[pc]
        after = snapshot(remote)
        if body_compute_events:
            after['master_compute'] = master_compute_snapshot(remote)
        if capture_focus:
            after['peer_input'] = peer_input_snapshot(remote)
        return dict(before=before, records=records, after=after,
                    sd_host_trace=sd_trace_snapshot(machine),
                    diagnostic_capture=capture_caller.report if capture_caller else None,
                    capture_wait_idle=capture_wait_idle,
                    capture_focus=capture_focus,
                    controller_step_link=getattr(machine.args, 'controller_step_link', False),
                    controller_actuator=getattr(machine.args, 'controller_actuator', False),
                    sampling_output_complete=getattr(machine.args, 'sampling_output_complete', False),
                    primary_exposure_sync=getattr(machine.args, 'primary_exposure_sync', False),
                    controller_step_trigger=dict(requested=controller_step_trigger,
                                                 supplied=controller_step_trigger_sent),
                    capture_counter_window=(dict(requested_seconds=capture_counter_seconds,
                        reached=bool(capture_caller.report['triggered'] and
                            after['counter_ticks'] - capture_caller.report['trigger_counter_ticks'] >=
                            capture_counter_seconds * before['counter_frequency']))
                        if capture_counter_seconds is not None else None),
                    observed_seconds=round(time.monotonic() - started, 3),
                    observed_counter_seconds=round((after['counter_ticks'] - before['counter_ticks']) /
                                                   before['counter_frequency'], 6),
                    driver_notification_hits=callback_hits,
                    tail_frame_events=tail_events,
                    mode1_frame_events=mode1_events,
                    memory_watch=(dict(address=hex(watch_address), bytes=watch_bytes,
                                       limit=watch_count, observed=watched_count)
                                  if watch_address is not None else None),
                    shutter_on_preview=shutter_on_preview,
                    preview_press_sent=preview_press_sent and not capture_submit_on_ready,
                    half_before_full=half_before_full, preview_half_sent=preview_half_tick is not None,
                    input_boundary_events=input_boundary_events,
                    shutter_on_ready=shutter_on_ready,
                    application_only=application_only,
                    image_work_events=image_work_events,
                    body_state_events=body_state_events,
                    body_capture_events=body_capture_events,
                    body_periodic_operations=body_periodic_operations,
                    body_input_events=body_input_events,
                    body_input_samples=body_input_samples,
                    body_compute_events=body_compute_events,
                    body_system_events=body_system_events,
                    shutter_click=click,
                    unseen=[label for address, label in armed.items()
                            if not hits.get(address, 0) and
                            not (capture_caller and capture_caller.ui_hits.get(address, 0)) and
                            (address != 0x10321a4c or callback_hits == 0)])
    finally:
        remote.sock.settimeout(15)
        if capture_caller:
            capture_caller.close()
        if memory_watch_armed:
            remote.command(f'z{watch_type},{watch_address:x},{watch_bytes:x}')
        if breakpoints_installed:
            for address in armed:
                remote.breakpoint(address, False)
        remote.command('D')
        remote.sock.close()
        if playback:
            machine.set_key(8, 1)
        machine.set_key(25, 1)
        machine.set_key(24, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--wsl', action='store_true')
    parser.add_argument('--sd-card', type=Path)
    parser.add_argument('--trace-sd-host', action='store_true',
                        help='Record bounded SD command/DMA metadata; keep raw traces private')
    parser.add_argument('--display-complete', action='store_true')
    parser.add_argument('--input-handshake', action='store_true',
                        help='Enable the optional output-triggered laboratory GPIO handshake response')
    parser.add_argument('--frame-phase', action='store_true',
                        help='Enable the optional masked periodic sampling phase source')
    parser.add_argument('--input-stop-complete', action='store_true',
                        help='Enable the optional command-triggered input stop response')
    parser.add_argument('--frame-generate', action='store_true',
                        help='Enable the experimental RAW12 checkerboard input DMA source')
    parser.add_argument('--frame-notify', action='store_true',
                        help='Experimentally latch recovered input timing causes after successful DMA')
    parser.add_argument('--reconfigure-watch', type=int, default=0,
                        help='Wait up to this many host seconds for driver state 4 before tracing (0..900)')
    parser.add_argument('--tail-frame-events', action='store_true',
                        help='Laboratory input: pulse input causes 0/6 once after RAW stops in state 4')
    parser.add_argument('--mode1-frame-events', action='store_true',
                        help='Laboratory input: pulse bank 3 bit 7, then repeat after the first native output latch')
    parser.add_argument('--playback', action='store_true',
                        help='Observe the native playback capture-stop request instead of full release')
    parser.add_argument('--local-stop-events', action='store_true',
                        help='Laboratory input: pulse the enabled synchronization line at each local stop wait')
    parser.add_argument('--round-trip', action='store_true',
                        help='After playback, half-press to return to shooting and observe full release')
    parser.add_argument('--gpio-handshake-events', action='store_true',
                        help='Laboratory input: pulse GPIO input 0 at armed return-path handshake waits/submissions')
    parser.add_argument('--return-watch', type=int, default=120,
                        help='Host seconds to trace the return from playback (30..900)')
    parser.add_argument('--watch', type=int, default=30,
                        help='Host seconds to observe the requested stage (10..3600)')
    parser.add_argument('--capture-card-copy', type=Path,
                        help='Create a new persistent private card copy for capture file inspection')
    parser.add_argument('--icount-shift', type=int, default=0,
                        help='Diagnostic virtual nanoseconds per instruction as a power of two (0..6)')
    parser.add_argument('--capture-counter-seconds', type=float,
                        help='End focused capture observation after this many camera counter seconds from submission')
    parser.add_argument('--capture-exposure', type=int,
                        help='Set original program 1 and exposure property 0x500d; require readback before submission')
    capture_formats = parser.add_mutually_exclusive_group()
    capture_formats.add_argument('--capture-jpeg', action='store_true',
                        help='Use the original single-capture format 0x3801 request field')
    capture_formats.add_argument('--capture-format-3800', action='store_true',
                        help='Use the original format 0x3800 request field; does not establish a saved RAW image')
    parser.add_argument('--capture-storage', type=int, choices=(0, 1, 2), default=0,
                        help='Original capture target: 0 default, 1 slot 1, 2 slot 2')
    parser.add_argument('--boot-watch', type=int, default=240,
                        help='Host seconds to wait for the shooting foreground (30..600)')
    parser.add_argument('--watch-read', type=lambda value: int(value, 0),
                        help='Capture and single-step watched reads; the default access limit is one')
    parser.add_argument('--watch-write', type=lambda value: int(value, 0),
                        help='Capture and single-step watched writes; the default access limit is one')
    parser.add_argument('--watch-bytes', type=int, default=4,
                        help='Power-of-two memory watch window size in bytes (4..256)')
    parser.add_argument('--watch-count', type=int, default=1,
                        help='Stop an observed stage after this many watched accesses (1..64)')
    parser.add_argument('--frame-process', action='store_true',
                        help='Enable the functional full-scale RAW12 to monochrome preview path')
    parser.add_argument('--shutter-on-preview', action='store_true',
                        help='Leave shutter contacts released until a display submission follows processed pixels')
    parser.add_argument('--half-before-full', action='store_true',
                        help='After preview starts, hold half-press for at least half a counter second before full-press')
    parser.add_argument('--input-boundary-events', action='store_true',
                        help='Laboratory input: pulse supported masked boundary causes at native waits after RAW DMA advances')
    parser.add_argument('--shutter-on-ready', action='store_true',
                        help='Full-press at a processed display submission after the native release gate clears')
    parser.add_argument('--capture-submit-on-ready', action='store_true',
                        help='Diagnostic native-task capture API call after preview and release readiness')
    parser.add_argument('--trace-capture-resource-boot', action='store_true',
                        help='Observe capture resource bits 37/44 being written from reset')
    parser.add_argument('--trace-capture-compute-boot', action='store_true',
                        help='Observe the slave compute program loader from reset')
    parser.add_argument('--trace-primary-allocation-boot', action='store_true',
                        help='Observe the C 1.70 primary allocation source and constructor arguments from reset')
    parser.add_argument('--processing-resource-header', action='store_true',
                        help='Supply group 23 with a zero experimental body and native storage trailer')
    parser.add_argument('--aux-image-process', action='store_true',
                        help='Enable experimental grayscale block matching for auxiliary image requests')
    parser.add_argument('--capture-wait-idle', action='store_true',
                        help='Defer the diagnostic capture until the native filtered resource intersection clears')
    parser.add_argument('--capture-focus', action='store_true',
                        help='Trace diagnostic capture admission, stop and primary allocation without background input work')
    parser.add_argument('--controller-step-trigger', action='store_true',
                        help='Laboratory input: pulse and restore controller G8 after native capture preparation arms it')
    parser.add_argument('--controller-actuator', action='store_true',
                        help='Enable experimental PWM-driven controller position feedback')
    parser.add_argument('--controller-step-link', action='store_true',
                        help='Enable the experimental engine handshake to controller G8 connection')
    parser.add_argument('--sampling-output-complete', action='store_true',
                        help='Enable experimental single-comparison sampling output events')
    parser.add_argument('--primary-exposure-sync', action='store_true',
                        help='Experimentally defer primary pixels until the output-16 comparison')
    parser.add_argument('--application-only', action='store_true',
                        help='Limit body-shutter tracing to application, timer and capture entries')
    parser.add_argument('--shutter-click', action='store_true',
                        help='Release full and half contacts after at least a quarter counter second')
    parser.add_argument('--image-work-events', action='store_true',
                        help='After preview readiness, trace eight image scheduler requests per point instead of configuration nodes')
    parser.add_argument('--body-state-events', action='store_true',
                        help='Trace eight body state-update conditions per point instead of configuration nodes')
    parser.add_argument('--body-capture-events', action='store_true',
                        help='Trace capture operation registration and state requests after preview readiness')
    parser.add_argument('--body-input-events', action='store_true',
                        help='Trace release-contact changes through background input queuing before foreground dispatch')
    parser.add_argument('--body-compute-events', action='store_true',
                        help='Observe master compute requests during body input and compare the loaded program digest')
    parser.add_argument('--body-system-events', action='store_true',
                        help='Observe system mode input callbacks, notifications and mode requests after preview readiness')
    args = parser.parse_args()
    require(not args.primary_exposure_sync or
            args.sampling_output_complete and args.frame_generate and args.frame_notify,
            'Primary exposure synchronization requires sampling output, pixel generation and notification')
    require(10 <= args.watch <= 3600, 'Watch time out of bounds')
    require(not args.trace_sd_host or args.sd_card is not None,
            'SD tracing requires an attached card')
    require(args.capture_card_copy is None or args.sd_card is not None and args.capture_focus,
            'Persistent capture card requires a supplied card and focused capture tracing')
    require(args.capture_card_copy is None or
            args.capture_card_copy.resolve().is_relative_to((ROOT / '.local').resolve()),
            'Capture card copy must remain in the private .local directory')
    require(0 <= args.icount_shift <= 6, 'Instruction clock shift out of bounds')
    require(args.capture_counter_seconds is None or
            args.capture_focus and 0 < args.capture_counter_seconds <= 120,
            'Camera counter window requires focused capture and a duration up to 120 seconds')
    require(0 <= args.reconfigure_watch <= 900, 'Reconfiguration watch time out of bounds')
    require(not args.tail_frame_events or args.reconfigure_watch and args.frame_notify,
            'Tail event experiment requires reconfiguration observation and frame notification')
    require(not args.mode1_frame_events or args.reconfigure_watch and args.frame_notify,
            'Mode 1 event experiment requires reconfiguration observation and frame notification')
    require(not (args.tail_frame_events and args.mode1_frame_events),
            'Select one reconfiguration event experiment')
    require(30 <= args.boot_watch <= 600, 'Boot watch time out of bounds')
    require(args.watch_read is None or 0 <= args.watch_read <= 0xfffffffc and
            args.watch_read % 4 == 0, 'Read watch address out of bounds')
    require(args.watch_write is None or 0 <= args.watch_write <= 0xfffffffc and
            args.watch_write % 4 == 0, 'Write watch address out of bounds')
    require(args.watch_read is None or args.watch_write is None, 'Choose one memory watch type')
    require(4 <= args.watch_bytes <= 256 and args.watch_bytes & (args.watch_bytes - 1) == 0,
            'Memory watch window size out of bounds')
    require(1 <= args.watch_count <= 64, 'Memory watch access count out of bounds')
    require(all(address is None or address + args.watch_bytes <= 0x100000000
                for address in (args.watch_read, args.watch_write)), 'Memory watch range wraps')
    require(not args.frame_notify or args.frame_generate, 'Frame notification requires generated input pixels')
    require(not args.frame_process or args.frame_generate, 'Frame processing requires generated input pixels')
    require(not args.shutter_on_preview or args.frame_process and
            not args.playback, 'Preview shutter requires processing and a shooting observation')
    require(not args.half_before_full or args.shutter_on_preview or args.shutter_on_ready,
            'Staged shutter requires preview- or readiness-triggered input')
    require(not args.input_boundary_events or args.frame_generate and args.frame_notify and
            args.reconfigure_watch and not args.playback,
            'Input boundary experiment requires RAW DMA and shooting reconfiguration observation')
    require(not args.shutter_on_ready or args.frame_process and
            not args.playback and not args.shutter_on_preview,
            'Ready shutter requires processing and shooting observation without preview-triggered input')
    require(not args.capture_submit_on_ready or args.frame_process and
            not (args.playback or args.shutter_on_ready or args.shutter_on_preview or args.half_before_full),
            'Diagnostic capture requires processing and shooting observation without body shutter input')
    require(not args.capture_wait_idle or args.capture_submit_on_ready,
            'Idle capture observation requires the diagnostic native capture caller')
    require(args.capture_exposure is None or
            args.capture_submit_on_ready and 0 < args.capture_exposure <= 0xFFFFFFFF,
            'Exposure setting requires the diagnostic caller and a positive 32-bit property value')
    require(not args.capture_jpeg or args.capture_submit_on_ready,
            'Explicit JPEG format requires the diagnostic capture caller')
    require(not args.capture_format_3800 or args.capture_submit_on_ready,
            'Explicit format 0x3800 requires the diagnostic capture caller')
    require(not args.capture_storage or args.capture_submit_on_ready,
            'Explicit capture storage requires the diagnostic capture caller')
    require(not args.capture_focus or args.capture_submit_on_ready and not args.reconfigure_watch,
            'Focused capture requires the diagnostic caller without reconfiguration tracing')
    require(not args.controller_step_trigger or args.capture_focus,
            'Controller step input experiment requires focused capture tracing')
    require(sum((args.trace_primary_allocation_boot, args.trace_capture_resource_boot,
                 args.trace_capture_compute_boot)) <= 1,
            'Select one boot observation')
    require(not args.application_only or (args.shutter_on_ready or args.shutter_on_preview) and
            not (args.playback or args.capture_submit_on_ready or args.input_boundary_events),
            'Application-only observation requires a processed-preview body shutter')
    require(not args.shutter_click or args.shutter_on_ready or args.shutter_on_preview,
            'Shutter click requires a processed-preview body shutter')
    require(not args.image_work_events or args.application_only,
            'Image work observation requires application-only body shutter tracing')
    require(not args.body_state_events or (args.application_only and not args.image_work_events),
            'Body state observation requires application-only tracing without image work events')
    require(not args.body_capture_events or (args.application_only and
            not (args.body_state_events or args.image_work_events)),
            'Body capture observation requires application-only tracing without other work events')
    require(not args.body_input_events or (args.application_only and
            not (args.body_capture_events or args.body_state_events or args.image_work_events)),
            'Body input observation requires application-only tracing without other work events')
    require(not args.body_compute_events or (args.application_only and
            not (args.body_capture_events or args.body_state_events or args.body_input_events or args.image_work_events)),
            'Body compute observation requires application-only tracing without other work events')
    require(not args.body_system_events or (args.application_only and
            not (args.body_compute_events or args.body_capture_events or args.body_state_events or
                 args.body_input_events or args.image_work_events)),
            'Body system observation requires application-only tracing without other work events')
    require(30 <= args.return_watch <= 900, 'Return watch time out of bounds')
    require(not args.local_stop_events or args.playback, 'Local stop events require playback')
    require(not args.round_trip or args.playback, 'Round trip requires playback')
    require(not args.gpio_handshake_events or args.round_trip,
            'GPIO handshake events require a round trip')
    args.realtime = args.auto_menu = False
    args.update_store = ROOT / '.local/body-shutter-gate-store'
    args.update_image = None
    if args.trace_primary_allocation_boot:
        from tools.capture_allocation_boot_trace import CaptureAllocationMachine
        machine = CaptureAllocationMachine(args)
    elif args.trace_capture_resource_boot:
        from tools.capture_resource_boot_trace import CaptureResourceMachine
        machine = CaptureResourceMachine(args)
    elif args.trace_capture_compute_boot:
        from tools.capture_compute_boot_trace import CaptureComputeMachine
        machine = CaptureComputeMachine(args)
    else:
        machine = Machine(args)
    try:
        machine.restart()
        deadline = time.monotonic() + args.boot_watch
        while time.monotonic() < deadline:
            state = machine.status()
            if state['phase'] == 'failed':
                raise RuntimeError(state['error'])
            if state.get('ready') and state.get('index') == 3 and state.get('input_ready'):
                break
            time.sleep(1)
        else:
            report = dict(observation='shooting-startup-deadline', boot=state,
                          boot_watch_seconds=args.boot_watch,
                          icount_shift=args.icount_shift,
                          sampling_output_complete=args.sampling_output_complete,
                          primary_exposure_sync=args.primary_exposure_sync,
                          preserved_card_name=args.capture_card_copy.name if args.capture_card_copy else None,
                          display_complete=args.display_complete,
                          input_handshake=args.input_handshake, frame_phase=args.frame_phase,
                          input_stop_complete=args.input_stop_complete,
                          frame_generate=args.frame_generate,
                          frame_notify=args.frame_notify,
                          shooting_foreground_ready=False)
            # A running console has detached its startup observer. Preserve
            # the failed foreground's actual state before closing the VM.
            if state['phase'] == 'running':
                with machine.io:
                    machine.qmp.command('stop')
                    remote = Remote(machine.gdb_port)
                    try:
                        report['snapshot'] = snapshot(remote)
                    finally:
                        remote.command('D')
                        remote.sock.close()
                report['native_lcd'] = lcd_snapshot(machine)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
            raise TimeoutError('Shooting foreground did not become ready')
        reconfiguration = None
        if args.reconfigure_watch:
            started = time.monotonic()
            driver_state = None
            reached = False
            while time.monotonic() - started < args.reconfigure_watch:
                machine.heartbeat()
                with machine.io:
                    driver_state = (machine._words(0xb1868af0, 1)[0] >> 8) & 255
                    finite_ready = (not args.mode1_frame_events or
                                    machine._bytes(0xb1888147, 1)[0] == 1 and
                                    machine._words(0xb26b38cc, 1)[0] & 4)
                if driver_state == 4 and finite_ready:
                    reached = True
                    break
                time.sleep(1)
            reconfiguration = dict(driver_state=driver_state, reached=reached,
                                   host_seconds=round(time.monotonic() - started, 3))
            print(json.dumps(dict(reconfiguration_wait=reconfiguration)), flush=True)
        initial_lcd = lcd_snapshot(machine)
        initial_dma = input_dma_snapshot(machine) if args.frame_generate else None
        report = dict(observation=('native-playback-capture-stop' if args.playback else
                                  'native-full-release-application-gate'), boot=state,
                      sd_attached=args.sd_card is not None,
                      sd_image_bytes=args.sd_card.stat().st_size if args.sd_card else None,
                      display_complete=args.display_complete, watch_seconds=args.watch,
                      icount_shift=args.icount_shift,
                      sd_snapshot=args.capture_card_copy is None,
                      preserved_card_name=args.capture_card_copy.name if args.capture_card_copy else None,
                      input_handshake=args.input_handshake,
                      frame_phase=args.frame_phase,
                      input_stop_complete=args.input_stop_complete,
                      frame_generate=args.frame_generate,
                      frame_notify=args.frame_notify,
                      frame_process=args.frame_process,
                      aux_image_process=args.aux_image_process,
                      local_stop_events=args.local_stop_events,
                      gpio_handshake_events=args.gpio_handshake_events,
                      round_trip=args.round_trip,
                      reconfiguration_wait=reconfiguration,
                      return_watch_seconds=args.return_watch,
                      trace=observe(machine, args.watch, args.playback, args.local_stop_events,
                                    watch_read=args.watch_read, watch_write=args.watch_write,
                                    watch_bytes=args.watch_bytes, watch_count=args.watch_count,
                                    shutter_on_preview=args.shutter_on_preview,
                                    half_before_full=args.half_before_full,
                                    input_boundary_events=args.input_boundary_events,
                                    shutter_on_ready=args.shutter_on_ready,
                                    capture_submit_on_ready=args.capture_submit_on_ready,
                                    capture_wait_idle=args.capture_wait_idle,
                                    capture_focus=args.capture_focus,
                                    capture_counter_seconds=args.capture_counter_seconds,
                                    capture_exposure=args.capture_exposure,
                                    capture_jpeg=args.capture_jpeg,
                                    capture_format_3800=args.capture_format_3800,
                                    capture_storage=args.capture_storage,
                                    controller_step_trigger=args.controller_step_trigger,
                                    application_only=args.application_only,
                                    shutter_click=args.shutter_click,
                                    image_work_events=args.image_work_events,
                                    body_state_events=args.body_state_events,
                                    body_capture_events=args.body_capture_events,
                                    body_input_events=args.body_input_events,
                                    body_compute_events=args.body_compute_events,
                                    body_system_events=args.body_system_events,
                                    frame_notify=args.frame_notify,
                                    reconfigure=bool(args.reconfigure_watch),
                                    tail_frame_events=args.tail_frame_events,
                                    mode1_frame_events=args.mode1_frame_events))
        report['native_lcd_before'] = initial_lcd
        report['processing_resource_header'] = args.processing_resource_header
        if args.trace_capture_resource_boot:
            report['capture_resource_boot_writes'] = machine.resource_boot_writes
        if args.trace_capture_compute_boot:
            report['capture_compute_boot'] = machine.compute_boot
        if args.trace_primary_allocation_boot:
            report['primary_allocation_boot_writes'] = machine.allocation_boot_writes
        if initial_dma is not None:
            report['input_dma_before'] = initial_dma
        report['final_application'] = machine.status()
        if args.round_trip and report['final_application']['index'] == 2:
            trace = observe(machine, args.return_watch, returning=True,
                            gpio_handshake_events=args.gpio_handshake_events,
                            watch_write=args.watch_write, frame_notify=args.frame_notify,
                            watch_bytes=args.watch_bytes, watch_count=args.watch_count)
            state = machine.status()
            report['return_liveview'] = dict(application=state, trace=trace)
            if state['index'] == 3 and state['input_ready']:
                report['shutter_after_return'] = observe(machine, 30, watch_write=args.watch_write,
                    frame_notify=args.frame_notify, watch_bytes=args.watch_bytes, watch_count=args.watch_count)
                report['post_shutter_application'] = machine.status()
        report['native_lcd_after'] = lcd_snapshot(machine)
        if args.frame_generate:
            report['input_dma_after'] = input_dma_snapshot(machine)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
    finally:
        machine.close()


if __name__ == '__main__':
    main()
