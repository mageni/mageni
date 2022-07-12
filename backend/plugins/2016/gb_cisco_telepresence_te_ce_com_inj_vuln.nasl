###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco TelePresence CE and TC Software Command Injection Vulnerability(cisco-sa-20161102-tp)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.809729");
  script_version("2019-05-10T14:24:23+0000");
  script_cve_id("CVE-2016-6459");
  script_bugtraq_id(94075);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2016-11-21 11:42:31 +0530 (Mon, 21 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cisco TelePresence CE and TC Software Command Injection Vulnerability(cisco-sa-20161102-tp)");

  script_tag(name:"summary", value:"The host is running Cisco TelePresence
  Endpoint and is prone to local command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input
  sanitization of some commands.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute local shell commands with commands injected as parameters.
  Also the attacker can retrieve full information from the device including
  private keys.");

  script_tag(name:"affected", value:"All TelePresence endpoints running following
  CE or TC software are affected:
  Cisco TelePresence CE Software 8.1.0,
  Cisco TelePresence CE Software 8.0.0,
  Cisco TelePresence TC Software 7.3.0,
  Cisco TelePresence TC Software 7.3.1,
  Cisco TelePresence TC Software 7.3.2,
  Cisco TelePresence TC Software 7.3.3,
  Cisco TelePresence TC Software 7.1.0,
  Cisco TelePresence TC Software 7.1.1,
  Cisco TelePresence TC Software 7.1.2,
  Cisco TelePresence TC Software 7.1.3,
  Cisco TelePresence TC Software 7.1.4");

  script_tag(name:"solution", value:"Apply updates as available from vendor.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb25010");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161102-tp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_telepresence_detect_snmp.nasl", "gb_cisco_telepresence_detect_ftp.nasl");
  script_mandatory_keys("cisco/telepresence/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cisport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!version =  get_app_version(cpe:CPE, port:cisport)){
  exit(0);
}

##TE and CE affected but pattern coming like this only
ciscoVer = eregmatch(pattern:"^T[CE]([^$]+$)", string:version, icase:TRUE);
if(isnull(ciscoVer[1])){
  exit(0);
}

verscat = ciscoVer[0];
vers = ciscoVer[1];

if(verscat =~ "^ce.")
{
  if(vers =~ "^8\.0\.0" || vers =~ "^8\.1\.0\."){
    VULN = TRUE;
  }
}
else if(verscat =~ "^tc.")
{
  if(vers =~ "^7\.1\.[0-4]" || vers =~ "^7\.3\.[0-3]"){
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:vers, fixed_version: "See advisory" );
  security_message( port:cisport, data:report);
  exit(0);
}
exit( 99 );
