###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_telepresence_te_tc_67170.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Cisco TelePresence TC and TE Software Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:telepresence_mcu_mse_series_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105026");
  script_bugtraq_id(67170);
  script_cve_id("CVE-2014-2162", "CVE-2014-2163", "CVE-2014-2164", "CVE-2014-2165", "CVE-2014-2166", "CVE-2014-2167", "CVE-2014-2168", "CVE-2014-2169", "CVE-2014-2170", "CVE-2014-2171", "CVE-2014-2172", "CVE-2014-2173", "CVE-2014-2175");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11867 $");

  script_name("Cisco TelePresence TC and TE Software Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67170");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140430-tcte");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-12 16:46:52 +0200 (Mon, 12 May 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_telepresence_detect_snmp.nasl", "gb_cisco_telepresence_detect_ftp.nasl");
  script_mandatory_keys("cisco/telepresence/typ", "cisco/telepresence/version");

  script_tag(name:"impact", value:"Attackers can exploit these issues to execute arbitrary code in the
context of the device, bypass authentication mechanisms, gain
unauthorized access, execute arbitrary commands, or cause denial-of-
service conditions. Other attacks may also be possible.");
  script_tag(name:"vuldetect", value:"Check the Firmware-Version.");
  script_tag(name:"insight", value:"Cisco TelePresence TC and TE Software are prone to
the following security vulnerabilities:

1. Multiple remote denial-of-service vulnerabilities

2. A buffer-overflow vulnerability

3. A command-injection vulnerability

4. A command-injection vulnerability

5. A heap-based buffer-overflow vulnerability

6. A local buffer-overflow vulnerability

7. A local authentication-bypass vulnerability

8. A remote denial-of-service vulnerability");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Cisco TelePresence TC and TE Software are prone to multiple
security vulnerabilities.");
  script_tag(name:"affected", value:"Cisco TelePresence MX Series

Cisco TelePresence System EX Series

Cisco TelePresence Integrator C Series

Cisco TelePresence Profiles Series

Cisco TelePresence Quick Set Series

Cisco TelePresence System T Series

Cisco TelePresence VX Clinical Assistant");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers =  get_app_version(cpe:CPE) ) exit( 0 );
if( ! typ = get_kb_item( "cisco/telepresence/typ" ) ) exit( 0 );

if( typ !~ ' T(1|3)$' && typ !~ ' EX(6|9)0$' && typ !~ ' C(2|4|6|9)0$' &&
    typ !~ ' SX(1|2|8)0$' && typ !~ ' T(1|3)$' && typ !~ 'MX(2|3|7|8)00$' && typ !~ 'G2$'
    && typ !~ 'SpeakerTrack$' && typ !~ ' (42|52)/55( Dual$)'
    && typ !~ ' (42|52)/55( C40$)' )  exit( 0 );

version = eregmatch(pattern: "^T[CE]([^$]+$)", string:vers, icase:TRUE);
if( isnull( version[1] ) ) exit( 0 );
vers = version[1];
if( vers =~ "^(4|5|6)\.") fix = "6.3.1";
if( vers =~ "^7\.")       fix = "7.1.1";
if( ! fix ) exit( 0 );
if( version_is_less( version:vers, test_version:fix ) )
{
  report = 'Installed version: ' + vers + '\nFixed version:     ' + fix;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
