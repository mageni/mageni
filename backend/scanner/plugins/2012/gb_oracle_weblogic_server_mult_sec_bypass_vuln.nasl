##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_weblogic_server_mult_sec_bypass_vuln.nasl 11355 2018-09-12 10:32:04Z asteins $
#
# Oracle WebLogic Server Multiple Security Bypass Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:bea:weblogic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802446");
  script_version("$Revision: 11355 $");
  script_bugtraq_id(54870, 54839);
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:32:04 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-08-28 1:34:53 +0530 (Tue, 28 Aug 2012)");

  script_name("Oracle WebLogic Server Multiple Security Bypass Vulnerabilities");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Aug/50");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20319/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20318/");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/9sg_ora2.htm");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("oracle_webLogic_server_detect.nasl");
  script_mandatory_keys("OracleWebLogicServer/installed");
  script_require_ports("Services/www", 7001);

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code under
the context of the application.");

  script_tag(name:"affected", value:"Oracle WebLogic Server version 12c (12.1.1)");

  script_tag(name:"insight", value:"- Soap interface exposes the 'deleteFile' function which could allow to
delete arbitrary files with administrative privileges on the target server through a directory traversal
vulnerability.

  - A web service called 'FlashTunnelService' which can be reached without prior authentication and processes
incoming SOAP requests.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Oracle WebLogic Server and is prone to multiple
security bypass vulnerabilities");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_equal(version:vers, test_version:"12.1.1")) {
  security_message(port:port);
  exit(0);
}

exit(99);
