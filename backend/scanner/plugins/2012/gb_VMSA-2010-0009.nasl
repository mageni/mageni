###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2010-0009.nasl 14187 2019-03-14 14:09:52Z cfischer $
#
# VMSA-2010-0009 ESXi utilities and ESX Service Console third party updates
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103468");
  script_cve_id("CVE-2009-2695", "CVE-2009-2908", "CVE-2009-3228", "CVE-2009-3286", "CVE-2009-3547",
                "CVE-2009-3613", "CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726",
                "CVE-2007-4567", "CVE-2009-4536", "CVE-2009-4537", "CVE-2009-4538", "CVE-2006-6304",
                "CVE-2009-2910", "CVE-2009-3080", "CVE-2009-3556", "CVE-2009-3889", "CVE-2009-3939",
                "CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4138", "CVE-2009-4141", "CVE-2009-4272",
                "CVE-2009-3563", "CVE-2009-4355", "CVE-2009-2409", "CVE-2009-0590", "CVE-2009-1377",
                "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1386", "CVE-2009-1387", "CVE-2009-4212",
                "CVE-2009-1384", "CVE-2010-0097", "CVE-2010-0290", "CVE-2009-3736", "CVE-2010-0001",
                "CVE-2010-0426", "CVE-2010-0427", "CVE-2010-0382");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 14187 $");
  script_name("VMSA-2010-0009: ESXi utilities and ESX Service Console third party updates");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 15:09:52 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-04-16 10:53:01 +0100 (Mon, 16 Apr 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2010-0009.html");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2010-0009.");

  script_tag(name:"affected", value:"VMware ESXi 4.0.0 without patch ESXi400-201005401-SG

  VMware ESX 4.0.0 without patches ESX400-201005401-SG, ESX400-201005406-SG, ESX400-201005408-SG, ESX400-201005407-SG, ESX400-201005405-SG, ESX400-201005409-SG

  VMware ESX 3.5 without patches ESX350-201006408-SG, ESX350-201006405-SG, ESX350-201006406-SG");

  script_tag(name:"insight", value:"ESXi update for ntp and ESX Console OS (COS) updates for COS kernel, openssl, krb5, gcc, bind, gzip, sudo resolve multiple security issues:

  a. Service Console update for COS kernel

  Updated COS package 'kernel' addresses the security issues that are fixed through versions 2.6.18-164.11.1.

  b. ESXi userworld update for ntp

  A vulnerability in ntpd could allow a remote attacker to cause a denial of service (CPU and bandwidth consumption) by using MODE_PRIVATE
  to send a spoofed (1) request or (2) response packet that triggers a continuous exchange of MODE_PRIVATE error responses between two NTP daemons.

  c. Service Console package openssl updated to 0.9.8e-12.el5_4.1

  A memory leak in the zlib could allow a remote attacker to cause a denial of service (memory consumption) via vectors that trigger
  incorrect calls to the CRYPTO_cleanup_all_ex_data function.

  d. Service Console update for krb5 to 1.6.1-36.el5_4.1 and pam_krb5 to 2.2.14-15.

  Multiple integer underflows in the AES and RC4 functionality in the crypto library could allow remote attackers to cause a denial of
  service (daemon crash) or possibly execute arbitrary code by providing ciphertext with a length that is too short to be valid.

  e. Service Console package bind updated to 9.3.6-4.P1.el5_4.2

  A vulnerability was discovered which could allow remote attacker to add the Authenticated Data (AD) flag to a forged NXDOMAIN response
  for an existing domain.

  f. Service Console package gcc updated to 3.2.3-60

  GNU Libtool's ltdl.c attempts to open .la library files in the current working directory. This could allow a local user to gain
  privileges via a Trojan horse file. The GNU C Compiler collection (gcc) provided in ESX contains a statically linked version of the
  vulnerable code, and is being replaced.

  g. Service Console package gzip update to 1.3.3-15.rhel3

  An integer underflow in gzip's unlzw function on 64-bit platforms may allow a remote attacker to trigger an array index error
  leading to a denial of service (application crash) or possibly execute arbitrary code via a crafted LZW compressed file.

  h. Service Console package sudo updated to 1.6.9p17-6.el5_4

  When a pseudo-command is enabled, sudo permits a match between the name of the pseudo-command and the name of an executable file in an
  arbitrary directory, which allows local users to gain privileges via a crafted executable file.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("vmware_esx.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.0.0","ESXi400-201005401-SG");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);