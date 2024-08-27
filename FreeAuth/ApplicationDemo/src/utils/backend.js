const path = require('path')
const dns = require('dns')
const ffi = require('koffi')
const installDir = process.env.NODE_ENV === 'production' ? path.dirname(process.argv0) : process.cwd();
console.log(installDir);
const libsmtp = ffi.load(path.join(installDir, '/libs/libNodeWrapperSMTP' + ffi.extension));
const node_entry_point = libsmtp.func('bool node_entry_point(int verifier_port, int smtp_port, int smtp_method, char *smtp_ip, char *verifier_ip, char *username, char *passwd)');
const get_current_state_native = libsmtp.func('int get_current_state()');

export function emailVerifyNativeStarter(credential_json, successCall, failCall) {
    let method = 0;
    let credentials = JSON.parse(credential_json);
    console.log(process.argv0);
    switch (credentials.authmethod) {
        case 'LOGIN':
            method = 1;
            break;
        case 'PLAIN':
            method = 2;
            break;
        case 'OAuth2':
            method = 3;
            break;
    }

    dns.resolve4(credentials.hostname,
        (err, address) => {
            try {
            if (err) {
                    var rep = /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/;
                    if(!rep.test(credentials.hostname))
                        throw err;
                    address = [credentials.hostname];
            }
            console.log("SMTP server address: " + address[0]);
            let res = node_entry_point(credentials.v_port, credentials.port, method, address[0], credentials.v_hostname, credentials.email, credentials.code);
            if (!res) throw new Error('Native API failed!');
            } catch(e) {
                failCall(e);
                return;
            }
            successCall();
        });
}

export function getCurStateFromNative() {
    return get_current_state_native();
}