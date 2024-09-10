const vcodeMsg = [
    'Start email address verification process...',
    'Connected to verifier',
    'Preproc handshake circuits...done',
    'Three party handshake finished, connected to server',
    'Preproc AES-GCM-128 related circuits...done',
    'SMTP protocol authentication comleted...received 235',
    'Email address and addition account factor committed to verifier',
    'All done, verification process has been successfully completed',
    'Error! something got wrong in'
]

const vcodeRun = [
    'Start',
    'Connecting to verifier',
    'Preprocing handshake circuits',
    'Running three party handshake',
    'Preprocing some circuits',
    'Running SMTP protocol',
    'Commit to verifier'
]

const vstatus = {
    STATE_COMPLETE: 6,
    STATE_ERROR: 8
}

export {vcodeMsg, vcodeRun, vstatus}
