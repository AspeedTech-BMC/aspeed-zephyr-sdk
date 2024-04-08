1. Prepare environment.
   ```
   pip3 install crccheck
   pip3 install ecdsa
   git clone https://github.com/intel/intel-server-prot-spdm.git
   export PYTHONPATH=\<intel-server-prot-spdm path\>
   to apply the patch intel-server-prot-spdm.patch
   ```

2. to issue the below command to generate the BHS AFM template file (bhs_afm_manifest_pfm.json and bhs_afm_manifest_cap.json are the example files)
   ```
   python3 -m intelprot.capsule -start_afm -p bhs
   ```
   to replace root_private_key, csk_private_key, device_addr, afm_addr ... and all other necessary properties in bhs_afm_manifest.json
   Note. the json files for BMC PFM and AFM capsule should be separately. Normally, the json file for BMC PFM should only carry one device info and the json file for AFM capsule could carry multiple device info.

3. to use the json file in above step and issue the below command to generate the AFM image for BMC PFM
   ```
   python3 -m intelprot.capsule afm -a bhs_afm_manifest_pfm.json
   ```

4. to issue the below command to generate the BMC template file (bhs_pfr_bmc_manifest.json is the example file)
   ```
   python3 -m intelprot.bmc -start_build -r bhs
   ```
   to replace root_private_key, csk_private_key, svn and all other necessary properties in bhs_pfr_bmc_manifest.json and to add two properties afm_header and afm_active_capsule in build_image object. These images are generated in step 3.

5. to put the full-size bmc image and the json file to the same folder and issue the below command to generate the BMC signed image (full-size and capsule) and the generated image will be stored in Output folder.
   ```
   python3 -m intelprot.bmc -m bhs_pfr_bmc_manifest.json -r bhs
   ```

6. to issue the below command to generate the AFM capsule image.
   ```
   python3 -m intelprot.capsule afm -a bhs_afm_manifest_cap.json
   ```