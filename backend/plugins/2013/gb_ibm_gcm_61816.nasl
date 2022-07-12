###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_gcm_61816.nasl 14186 2019-03-14 13:57:54Z cfischer $
#
# IBM 1754 GCM16 and GCM32 Global Console Managers Multiple Command Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103768");
  script_bugtraq_id(61816);
  script_cve_id("CVE-2013-0526");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 14186 $");

  script_name("IBM 1754 GCM16 and GCM32 Global Console Managers Multiple Command Execution Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61816");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:57:54 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-08-19 15:12:16 +0200 (Mon, 19 Aug 2013)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"impact", value:"Successful exploit of these issues may allow an attacker to execute
  arbitrary commands with the privileges of the root user.");

  script_tag(name:"vuldetect", value:"Check if the firmware version is greater than 1.18.0.22011.");

  script_tag(name:"insight", value:"IBM 1754 GCM16 and GCM32 versions 1.18.0.22011 and below contain a flaw
  that allows a remote authenticated user to execute unauthorized commands as
  root. This flaw exist because webapp variables are not sanitized.");

  script_tag(name:"affected", value:"IBM 1754 GCM16 Global Console Manager 1.18.0.22011 and prior

  IBM 1754 GCM32 Global Console Manager 1.18.0.22011 and prior.");

  script_tag(name:"solution", value:"Updates (Version 1.18.0.22011) are available.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"IBM 1754 GCM16 and GCM32 Global Console Managers are prone to multiple
  command-execution vulnerabilities because they fail to sanitize user-supplied input.");

  exit(0);
}

include("version_func.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc || !egrep(pattern:"^GCM(16|32)", string:sysdesc))exit(0);

version = eregmatch(pattern:"GCM(16|32) ([0-9.]+)", string: sysdesc);
if(isnull(version[2]))exit(0);

vers = version[2];

if(version_is_less(version:vers, test_version:"1.18.0.22011")) {
  security_message(port:0);
  exit(0);
}

exit(99);