###############################################################################
# OpenVAS Vulnerability Test
# $Id: base_36830.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Basic Analysis and Security Engine Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Updated By Sooraj KS <kssooraj@secpod.com>
# date update: 2010/05/14
# Added CVE-2009-4837  CVE-2009-4838  CVE-2009-4839 and BID 18298
#
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

CPE = "cpe:/a:secureideas:base";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100323");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)");
  script_bugtraq_id(36830, 18298);
  script_cve_id("CVE-2009-4590", "CVE-2009-4591", "CVE-2009-4592", "CVE-2009-4837", "CVE-2009-4838", "CVE-2009-4839");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Basic Analysis and Security Engine Multiple Input Validation Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36830");
  script_xref(name:"URL", value:"http://secureideas.sourceforge.net/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("base_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BASE/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Basic Analysis and Security Engine (BASE) is prone to multiple
  input-validation vulnerabilities because it fails to adequately sanitize user-supplied input. These
  vulnerabilities include an SQL-injection issue, a cross-site scripting issue, and a local file-include issue.");

  script_tag(name:"impact", value:"Exploiting these issues can allow an attacker to steal cookie-based authentication
  credentials, view and execute local files within the context of the webserver, compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying database. Other attacks may also be possible.");

  script_tag(name:"affected", value:"These issues affect versions prior to BASE 1.4.4.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);