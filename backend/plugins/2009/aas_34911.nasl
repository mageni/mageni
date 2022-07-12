###############################################################################
# OpenVAS Vulnerability Test
# $Id: aas_34911.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# A-A-S Application Access Server Multiple Vulnerabilities
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

CPE = "cpe:/a:klinzmann:application_access_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100197");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-12 22:04:51 +0200 (Tue, 12 May 2009)");
  script_bugtraq_id(34911);
  script_cve_id("CVE-2009-1464", "CVE-2009-1465", "CVE-2009-1466");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("A-A-S Application Access Server Multiple Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("aas_detect.nasl");
  script_mandatory_keys("aas/detected");
  script_require_ports("Services/www", 6262);

  script_tag(name:"summary", value:"According to its version number, the remote version of A-A-S
  Application Access Server is prone to multiple security issues including a cross-site request-forgery
  vulnerability, an insecure-default-password vulnerability and an information-disclosure vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to run privileged commands on the
  affected computer and gain unauthorized administrative access to the affected application and the underlying system.");

  script_tag(name:"affected", value:"These issues affect version 2.0.48. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34911");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "2.0.48")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);