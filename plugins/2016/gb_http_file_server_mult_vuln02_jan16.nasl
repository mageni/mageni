###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_http_file_server_mult_vuln02_jan16.nasl 11473 2018-09-19 11:21:09Z asteins $
#
# HTTP File Server Remote Command Execution Vulnerability-02 Jan16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:httpfilesever:hfs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806814");
  script_version("$Revision: 11473 $");
  script_cve_id("CVE-2014-6287");
  script_bugtraq_id(69782);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-19 13:21:09 +0200 (Wed, 19 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-01-11 15:22:37 +0530 (Mon, 11 Jan 2016)");
  script_name("HTTP File Server Remote Command Execution Vulnerability-02 Jan16");

  script_tag(name:"summary", value:"This host is running HTTP File Server
  and is prone to remote command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper
  neutralization of Null byte or NUL character");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code by uploading a file with certain invalid
  UTF-8 byte sequences that are interpreted as executable macro symbols.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"HttpFileServer version 2.3g and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128593");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/251276");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39161/");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_http_file_server_detect.nasl");
  script_mandatory_keys("hfs/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

include("host_details.inc");

if(!hfsPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!hfsVer = get_app_version(cpe:CPE, port:hfsPort)){
 exit(0);
}

if(version_is_less_equal(version:hfsVer, test_version:"2.3g"))
{
  report = 'Installed Version: ' + hfsVer + '\n' +
           'Fixed Version: Not available' + '\n';
  security_message(port:hfsPort, data:report);
  exit(0);
}
