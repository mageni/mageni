# OpenVAS Vulnerability Test
# $Id: kerberos_CB-A08-0044.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: Kerberos < 1.6.4 vulnerability
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
# Updated By: Antu Sandi <santu@secpod.com> on 2010-07-06
#  Updated the CVE, BID and CVSS score
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90016");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-06-17 20:22:38 +0200 (Tue, 17 Jun 2008)");
  script_cve_id("CVE-2008-0948", "CVE-2008-0947", "CVE-2008-0063", "CVE-2008-0062");
  script_bugtraq_id(28302, 28303);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Kerberos < 1.6.4 vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/release");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"All Kerberos users should upgrade to the latest version:");
  script_tag(name:"summary", value:"The remote host is probably affected by the vulnerabilities described in
  CVE-2008-0062, CVE-2008-0063, CVE-2008-0947, CVE-2008-0948.");

  script_tag(name:"impact", value:"CVE-2008-0062: An unauthenticated remote attacker may cause a krb4-enabled
  KDC to crash, expose information, or execute arbitrary code. Successful exploitation of this vulnerability
  could compromise the Kerberos key database and host security on the KDC host.

  CVE-2008-0063: An unauthenticated remote attacker may cause a krb4-enabled KDC to expose information. It is
  theoretically possible for the exposed information to include secret key data on some platforms.

  CVE 2008-0947: Buffer overflow in the RPC library used by libgssrpc and kadmind in MIT Kerberos 5 (krb5) 1.4
  through 1.6.3 allows remote attackers to execute arbitrary code by triggering a large number of open file
  descriptors.

  CVE 2008-0948: Buffer overflow in the RPC library (lib/rpc/rpc_dtablesize.c) used by libgssrpc and kadmind in
  MIT Kerberos 5 (krb5) 1.2.2, and probably other versions before 1.3, when running on systems whose unistd.h does
  not define the FD_SETSIZE macro, allows remote attackers to cause a denial of service (crash) and possibly
  execute arbitrary code by triggering a large number of open file descriptors.");

  exit(0);
}

include("revisions-lib.inc");
include("version_func.inc");
include("pkg-lib-deb.inc");

kbrls = dpkg_get_ssh_release();
if(!kbrls)
  exit(0);

rls = NULL;
ver = NULL;
rel = NULL;
pkg = NULL;
rls[0] = "SUSE10.0";
ver[0] = "1.4.3";
rel[0] = "19.30.6";
pkg[0] = "krb5";
rls[1] = "SUSE10.1";
ver[1] = "1.4.3";
rel[1] = "19.30.6";
pkg[1] = "krb5";
rls[2] = "SUSE10.2";
ver[2] = "1.5.1";
rel[2] = "23.14";
pkg[2] = "krb5";
rls[3] = "SUSE10.3";
ver[3] = "1.6.2";
rel[3] = "22.4";
pkg[3] = "krb5";
rls[4] = "SUSE11.0";
ver[4] = "1.6.3";
rel[4] = "49";
pkg[4] = "krb5";
rls[5] = "SUSE10.0";
ver[5] = "1.4.3";
rel[5] = "19.30.6";
pkg[5] = "krb5-server";
rls[6] = "SUSE10.1";
ver[6] = "1.4.3";
rel[6] = "19.30.6";
pkg[6] = "krb5-server";
rls[7] = "SUSE10.2";
ver[7] = "1.5.1";
rel[7] = "23.14";
pkg[7] = "krb5-server";
rls[8] = "SUSE10.3";
ver[8] = "1.6.2";
rel[8] = "22.4";
pkg[8] = "krb5-server";
rls[9] = "SUSE11.0";
ver[9] = "1.6.3";
rel[9] = "49";
pkg[10] = "krb5-server";
rls[10] = "FC7";
ver[10] = "1.6.1";
rel[10] = "9.fc7";
pkg[11] = "krb5";
rls[11] = "FC8";
ver[11] = "1.6.2";
rel[11] = "14.fc8";
pkg[11] = "krb5";

foreach i (keys(rls)) {
  if( kbrls == rls[i] ) {
    rpms = get_kb_item("ssh/login/rpms");
    if(rpms) {
      pat = ";"+pkg[i]+"~([0-9\.\-]+)";
      version = get_string_version(text:rpms, ver_pattern:pat);
      if(!isnull(version)) {
        if( version_is_less(version:version[1], test_version:ver[i]) ) {
          security_message(port:0);
        } else {
          if( version_is_equal(version:version[1], test_version:ver[i]) ) {
            pat = version[0]+"~([0-9\.\-]+)";
            release = get_string_version(text:rpms, ver_pattern:pat);
            if(!isnull(release)) {
              if( version_is_less(version:release[1] ,test_version:rel[i]) ) {
                security_message(port:0);
              }
            }
          }
        }
      }
    }
  }
}

rls = NULL;
ver = NULL;
rel = NULL;
pkg = NULL;
rls[0] = "GENTOO";
pat = "app-crypt/mit-krb5-([a-zA-Z0-9\.\-]+)";
ver[0] = "1.6.3-r1";
if( kbrls == rls[0] ) {
  pkg = get_kb_item("ssh/login/pkg");
  if(pkg) {
    version = get_string_version(text:pkg, ver_pattern:pat);
    if(!isnull(version)) {
      security_message(port:0);
    }
  }
}

rls = NULL;
ver = NULL;
rel = NULL;
pkg = NULL;
rls[0] = "UBUNTU6.06 LTS";
ver[0] = "1.4.3-5ubuntu0.7";
pkg[0] = "libkadm55";
rls[1] = "UBUNTU6.10";
ver[1] = "1.4.3-9ubuntu1.6";
pkg[1] = "libkadm55";
rls[2] = "UBUNTU7.04";
ver[2] = "1.4.4-5ubuntu3.4";
pkg[2] = "libkadm55";
rls[3] = "UBUNTU7.10";
ver[3] = "1.6.dfsg.1-7ubuntu0.1";
pkg[3] = "libkadm55";
rls[4] = "UBUNTU6.06 LTS";
ver[4] = "1.4.3-5ubuntu0.7";
pkg[4] = "libkrb53";
rls[5] = "UBUNTU6.10";
ver[5] = "1.4.3-9ubuntu1.6";
pkg[5] = "libkrb53";
rls[6] = "UBUNTU7.04";
ver[6] = "1.4.4-5ubuntu3.4";
pkg[6] = "libkrb53";
rls[7] = "UBUNTU7.10";
ver[7] = "1.6.dfsg.1-7ubuntu0.1";
pkg[7] = "libkrb53";

foreach i (keys(rls)) {
  if( kbrls == rls[i] ) {
    if(isdpkgvuln(pkg:pkg[i], ver:ver[i], rls:rls[i])) {
      security_message(port:0);
    }
  }
}

exit(0);