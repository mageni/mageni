###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sophos_safeguard_priv_esc_vuln.nasl 11317 2018-09-11 08:57:27Z asteins $
#
# Sophos SafeGuard Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107327");
  script_version("$Revision: 11317 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 10:57:27 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-07-04 11:36:43 +0200 (Wed, 04 Jul 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_cve_id("CVE-2018-6851", "CVE-2018-6852", "CVE-2018-6853", "CVE-2018-6854", "CVE-2018-6855", "CVE-2018-6856", "CVE-2018-6857");
  script_name("Sophos SafeGuard Privilege Escalation Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_sophos_safeguard_detect_win.nasl");
  script_mandatory_keys("Sophos/SafeGuard/Win/Installed");
  script_tag(name:"summary", value:"Sophos SafeGuard Client Products are prone to privilege escalation vulnerabilities.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerabilities are present within all configurations of SafeGuard Enterprise
  (SGN), SafeGuard Easy (SGE) and SafeGuard LAN Crypt (SGLC) clients running on Windows. Exploitation of those
  vulnerabilities requires running malicious code on the target machine and can result in privilege escalation.
  This vulnerability is not remotely exploitable (i.e. over the network).");
  script_tag(name:"affected", value:"SafeGuard Enterprise Client 8.00.4 and earlier, SafeGuard Easy Client 7.00.2.35 and earlier,
  SafeGuard LAN Crypt Client 3.95.1.13 and earlier.");
  script_tag(name:"solution", value:"Upgrade to SafeGuard Enterprise Client 8.00.5, SafeGuard Easy Client 7.00.3 or SafeGuard LAN Crypt Client 3.95.2.");
  script_xref(name:"URL", value:"https://labs.nettitude.com/blog/cve-2018-6851-to-cve-2018-6857-sophos-privilege-escalation-vulnerabilities/");
  exit(0);
}

include ("host_details.inc");
include ("version_func.inc");

vuln = FALSE;

if( vers = get_app_version( cpe:"cpe:/a:sophos:safeguard_lan_crypt_encryption_client", nofork:TRUE ) ) {
  if( version_is_less( version:vers, test_version:"3.95.2" ) ) {
    vuln = TRUE;
    report = report_fixed_ver( installed_version:vers, fixed_version:"3.95.2" );
    security_message( data:report, port:0 );
  }
}

if( vers = get_app_version( cpe:"cpe:/a:sophos:safeguard_enterprise_device_encryption_client", nofork:TRUE ) ) {
  if( version_is_less( version:vers, test_version:"8.00.5" ) ) {
    vuln = TRUE;
    report = report_fixed_ver( installed_version:vers, fixed_version:"8.00.5" );
    security_message( data:report, port:0 );
  }
}

if( vers = get_app_version( cpe:"cpe:/a:sophos:safeguard_easy_device_encryption_client", nofork:TRUE ) ) {
  if( version_is_less( version:vers, test_version:"7.00.3" ) ) {
    vuln = TRUE;
    report = report_fixed_ver( installed_version:vers, fixed_version:"7.00.3" );
    security_message( data:report, port:0 );
  }
}

if( ! vuln )
  exit ( 99 );
else
  exit ( 0 );
