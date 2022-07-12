###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_space_JSA10727.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Junos Space: Multiple Vulnerabilities in Junos Space
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105608");
  script_cve_id("CVE-2016-1265", "CVE-2015-4748", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2659", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4749", "CVE-2015-2625");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12313 $");

  script_name("Junos Space: Multiple Vulnerabilities in Junos Space");

  script_xref(name:"URL", value:"http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10727&cat=SIRT_1&actp=LIST");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been addressed in Junos Space 15.2R1.

  These include cross site scripting (XSS), default passwords, information leak and command injection vulnerabilities.
  These vulnerabilities may potentially allow a remote unauthenticated network based attacker with access to Junos Space
  to execute arbitrary code on Junos Space or gain access to devices managed by Junos Space.
  These vulnerabilities were found during internal product testing. These issues have been assigned CVE-2016-1265.
  Oracle Java runtime was upgraded to 1.7.0 update 85 (from 1.7.0 update 79) which resolves:

  - CVE-2015-4748 - Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, JRockit R28.3.6, and Java SE Embedded 7u75
  and Embedded 8u33 allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Security.

  - CVE-2015-2601 - Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, JRockit R28.3.6, and Java SE Embedded 7u75
  and 8u33 allows remote attackers to affect confidentiality via vectors related to JCE.

  - CVE-2015-2613 - Unspecified vulnerability in Oracle Java SE 7u80 and 8u45, and Java SE Embedded 7u75 and 8u33 allows
  remote attackers to affect confidentiality via vectors related to JCE.

  - CVE-2015-2659 - Unspecified vulnerability in Oracle Java SE 8u45 and Java SE Embedded 8u33 allows remote attackers
  to affect availability via unknown vectors related to Security.

  - CVE-2015-2808 - The RC4 algorithm, as used in the TLS protocol and SSL protocol, does not properly combine state
  data with key data during the initialization phase, which makes it easier for remote attackers to conduct plaintext-recovery
  attacks against the initial bytes of a stream by sniffing network traffic that occasionally relies on keys affected by
  the Invariance Weakness, and then using a brute-force approach involving LSB values, aka the `Bar Mitzvah` issue.

  - CVE-2015-4000 - The TLS protocol 1.2 and earlier, when a DHE_EXPORT ciphersuite is enabled on a server but not on a client,
  does not properly convey a DHE_EXPORT choice, which allows man-in-the-middle attackers to conduct cipher-downgrade attacks by
  rewriting a ClientHello with DHE replaced by DHE_EXPORT and then rewriting a ServerHello with DHE_EXPORT replaced by DHE, aka the `Logjam` issue.

  - CVE-2015-4749 - Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, JRockit R28.3.6, and Java SE Embedded 7u75 and
  8u33 allows remote attackers to affect availability via vectors related to JNDI.

  - CVE-2015-2625 - Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, JRockit R28.3.6, and Java SE Embedded 7u75 and
  8u33 allows remote attackers to affect confidentiality via vectors related to JSSE.");

  script_tag(name:"solution", value:"The following software releases have been updated to resolve this specific issue: Junos Space 15.2R1 (released March 17, 2016) and all subsequent releases.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been addressed in Junos Space 15.2R1.");
  script_tag(name:"affected", value:"This issue can affect any product or platform running Junos Space before 15.2R1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-18 12:53:02 +0200 (Mon, 18 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("JunOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_junos_space_version.nasl");
  script_mandatory_keys("junos_space/installed");
  exit(0);
}

include("host_details.inc");
include("junos.inc");

cpe = 'cpe:/a:juniper:junos_space';

if( ! vers = get_app_version( cpe:cpe ) ) exit( 0 );

if( vers =~ "^15\.2" )
  fix = '15.2R1';
else
  fix = '15.1R3';

if( check_js_version( ver:vers, fix:fix ) )
{
  report = 'Installed Version: ' + vers + '\n' +
           'Fixed Version:     ' + fix;

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

