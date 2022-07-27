###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joo_smf_sh_up.nasl 11596 2018-09-25 09:49:46Z asteins $
#
# Joomla SmartFormer 2.4.1 Shell Upload Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107023");
  script_version("$Revision: 11596 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 11:49:46 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"creation_date", value:"2016-07-06 06:40:16 +0200 (Wed, 06 Jul 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Joomla SmartFormer 2.4.1 Shell Upload Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"insight", value:"The vulnerability is due to a Smartformer component which allows unauthorized
  access to certain files.");
  script_tag(name:"summary", value:"Detects the installed version of Joomla Smartformer.
  The script detects the version of Joomla Smartformer component on remote host and tells whether it is vulnerable or not.");
  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to upload shell files in an affected site.");
  script_tag(name:"affected", value:"Joomla Smartformer 2.4.1.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.itoris.com/joomla-extensions/");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137730/joomlasmartformer-shell.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:appPort)){
  exit(0);
}

url = dir + '/administrator/components/com_smartformer/smartformer_joomla1.5.xml';
sndReq = http_get( item: url, port:appPort );
rcvRes = http_keepalive_send_recv( port: appPort, data:sndReq, bodyonly:FALSE );

if (rcvRes !~ "<?xml version" && "Smart Former" >!< rcvRes && "joomla" >!< rcvRes) exit (0);

if(ve = egrep( pattern:'<version>([0-9])+', string:rcvRes) ) {
  tmpVer = eregmatch ( pattern:'<version>(([0-9])[.]([0-9])[.]([0-9]))', string: ve);
}

if(tmpVer[1] ) {
  smfVer = tmpVer[1];
}

if (version_is_equal (version: smfVer, test_version: "2.4.1")) {
  report = report_fixed_ver(installed_version:smfVer, fixed_version:"None Available");
  security_message(port:appPort, data:report);
  exit(0);
}

exit(99);
