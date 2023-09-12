import os
import configparser

config = configparser.ConfigParser()
config.read('programmer_preload_gen.conf')
workspace_path = config['PATH'].get('WorkspacePath', "../../../../")
workspace_path = os.path.abspath(workspace_path)
sample_path = workspace_path + '/aspeed-zephyr-project/apps/preload-fw/sample'

build_path = config['PATH'].get('BuildPath', workspace_path + '/build/')
socsec_path = config['PATH'].get('SocsecPath', workspace_path + '/socsec/')
mp_imgs_path = config['PATH'].get('MPImagePath', build_path + 'mp_imgs/')
otp_cfg = config['PATH'].get('OTPConfig', sample_path + '/otp/config/1060A2_ECDSA_MP.json')
otp_key_path = config['PATH'].get('OTPKeyPath', sample_path + '/otp/key')

rot_fw_key = config['KEY'].get('RoTFWKey', sample_path + '/otp/key/rk384_prv.pem')

pristine = config['BUILD_OPTION'].get('Pristine', 'always')

def gen_preload_fw():
    cmd = 'cd ' + workspace_path + \
            '; west build -b ast10x0_mp' + \
            ' -d ' + build_path + 'preload' + \
            ' aspeed-zephyr-project/apps/preload-fw' + \
            ' -p ' + pristine
    os.system(cmd)

    preload_fw = build_path + 'preload/zephyr/zephyr.bin'
    cmd = 'cp ' + preload_fw + ' ' + mp_imgs_path + 'preload.bin'
    os.system(cmd)
    return

def gen_rot_fw():
    cmd = 'cd ' + workspace_path + \
            '; west build -b ast1060_dcscm' + \
            ' -d ' + build_path + 'rot' + \
            ' aspeed-zephyr-project/apps/aspeed-pfr' + \
            ' -p ' + pristine
    os.system(cmd)
    return

def sign_rot_fw():
    unsigned_rot = build_path + 'rot/zephyr/zephyr.bin'
    cmd = 'mkdir -p ' + mp_imgs_path + \
            ';cd ' + socsec_path + \
            ';socsec make_secure_bl1_image --soc 1060 --algorithm ECDSA384 --bl1_image ' + \
            unsigned_rot + \
            ' --output ' + mp_imgs_path + 'rot.signed.bin' + \
            ' --ecdsa_sign_key ' + rot_fw_key
    os.system(cmd)
    return


def gen_otp_img():
    cmd = 'otptool make_otp_image ' + otp_cfg +' --no_last_bit' + \
    ' --key_folder ' + otp_key_path + \
    ' --output_folder ' + mp_imgs_path
    os.system(cmd)
    return

def gen_preload_bin_odm():
    preload = mp_imgs_path + 'preload.bin'
    signed_rot = mp_imgs_path + 'rot.signed.bin'
    otp_img = mp_imgs_path + 'otp-all.image'
    mp_final_img = mp_imgs_path + 'ast1060-mp-odm-all.bin'

    with open(preload, 'rb') as plf:
        preload_content = plf.read()

    with open(signed_rot, 'rb') as srf:
        rot_content = srf.read()

    with open(otp_img, 'rb') as otf:
        otp_content = otf.read()

    with open(mp_final_img, 'wb') as f:
        f.write(b'\xff' * 1024 * 1024)
        f.seek(0)
        f.write(preload_content)
        f.seek(0x40000)
        f.write(otp_content)
        f.seek(0x60000)
        f.write(rot_content)

    return

cmd = 'rm -rf ' + mp_imgs_path
os.system(cmd)
cmd = 'mkdir -p ' + mp_imgs_path
os.system(cmd)


gen_preload_fw()

# Customer's firmware and OTP image
gen_rot_fw()
sign_rot_fw()
gen_otp_img()
gen_preload_bin_odm()


print("workspace      : " + workspace_path)
print("build path     : " + build_path)
print("socsec path    : " + socsec_path)
print("OTP config     : " + otp_cfg)
print("OTP key        : " + otp_key_path)
print("ROT FW key     : " + rot_fw_key)
print("\nImage Path     : " + mp_imgs_path + "\n")
