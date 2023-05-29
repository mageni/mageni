# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2150.1");
  script_cve_id("CVE-2022-28737");
  script_tag(name:"creation_date", value:"2023-05-10 04:21:25 +0000 (Wed, 10 May 2023)");
  script_version("2023-05-10T09:37:12+0000");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2150-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2150-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232150-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shim' package(s) announced via the SUSE-SU-2023:2150-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for shim fixes the following issues:


Updated shim signature after shim 15.7 be signed back:
 signature-sles.x86_64.asc, signature-sles.aarch64.asc (bsc#1198458)


Add POST_PROCESS_PE_FLAGS=-N to the build command in shim.spec to
 disable the NX compatibility flag when using post-process-pe because
 grub2 is not ready. (bsc#1205588)


Enable the NX compatibility flag by default. (jsc#PED-127)


Update to 15.7 (bsc#1198458) (jsc#PED-127):

Make SBAT variable payload introspectable Reference MokListRT instead of MokList Add a link to the test plan in the readme.
[V3] Enable TDX measurement to RTMR register Discard load-options that start with a NUL Fixed load_cert_file bugs Add -malign-double to IA32 compiler flags pe: Fix image section entry-point validation make-archive: Build reproducible tarball mok: remove MokListTrusted from PCR 7

Other fixes:


Support enhance shim measurement to TD RTMR. (jsc#PED-1273)


shim-install: ensure grub.cfg created is not overwritten after installing grub related files

Add logic to shim.spec to only set sbat policy when efivarfs is writeable. (bsc#1201066)
Add logic to shim.spec for detecting --set-sbat-policy option before using mokutil to set sbat policy. (bsc#1202120)
Change the URL in SBAT section to mail:security@suse.de. (bsc#1193282)

Update to 15.6 (bsc#1198458):

MokManager: removed Locate graphic output protocol fail error message shim: implement SBAT verification for the shim_lock protocol post-process-pe: Fix a missing return code check Update github actions matrix to be more useful post-process-pe: Fix format string warnings on 32-bit platforms Allow MokListTrusted to be enabled by default Re-add ARM AArch64 support Use ASCII as fallback if Unicode Box Drawing characters fail make: don't treat cert.S specially shim: use SHIM_DEVEL_VERBOSE when built in devel mode Break out of the inner sbat loop if we find the entry.
Support loading additional certificates Add support for NX (W^X) mitigations.
Fix preserve_sbat_uefi_variable() logic SBAT Policy latest should be a one-shot pe: Fix a buffer overflow when SizeOfRawData > VirtualSize pe: Perform image verification earlier when loading grub Update advertised sbat generation number for shim Update SBAT generation requirements for 05/24/22 Also avoid CVE-2022-28737 in verify_image() by @vathpela

Update to 15.5 (bsc#1198458):

Broken ia32 relocs and an unimportant submodule change.
mok: allocate MOK config table as BootServicesData Don't call QueryVariableInfo() on EFI 1.10 machines (bsc#1187260)
Relax the check for import_mok_state() (bsc#1185261)
SBAT.md: trivial changes shim: another attempt to fix load options handling Add tests for our load options parsing.
arm/aa64: fix the size of .rela* sections mok: fix potential buffer overrun in import_mok_state mok: relax the maximum variable size check Don't unhook ExitBootServices when EBS protection is disabled ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'shim' package(s) on SUSE Linux Enterprise Server 12-SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"shim", rpm:"shim~15.7~22.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
