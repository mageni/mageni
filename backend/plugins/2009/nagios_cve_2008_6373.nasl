###############################################################################
# OpenVAS Vulnerability Test
# $Id: nagios_cve_2008_6373.nasl 12962 2019-01-08 07:46:53Z ckuersteiner $
#
# Nagios External Commands and Adaptive Commands Unspecified
# Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:nagios:nagios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100188");
  script_version("$Revision: 12962 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 08:46:53 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)");
  script_bugtraq_id(32611);
  script_cve_id("CVE-2008-6373");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios External Commands and Adaptive Commands Unspecified Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("nagios_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nagios/installed");

  script_tag(name:"solution", value:"The vendor has released updates.");

  script_tag(name:"summary", value:"Nagios is prone to an unspecified vulnerability related to the CGI
  submission of external commands and the processing of adaptive commands.

  The issue affects versions prior to Nagios 3.0.6.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32611");
  script_xref(name:"URL", value:"http://www.nagios.org/");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!vers = get_app_version(cpe:CPE, port:port))exit(0);

if(version_is_less(version: vers, test_version: "3.0.6")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "3.0.6");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
