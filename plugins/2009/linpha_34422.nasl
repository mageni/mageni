###############################################################################
# OpenVAS Vulnerability Test
# $Id: linpha_34422.nasl 11723 2018-10-02 09:59:19Z ckuersteiner $
#
# LinPHA 1.3.4 Multiple Cross-Site Scripting Vulnerabilities
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

CPE = "cpe:/a:linpha:linpha";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100120");
  script_version("$Revision: 11723 $");
  script_cve_id("CVE-2014-7265");
  script_bugtraq_id(34422);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-02 11:59:19 +0200 (Tue, 02 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-04-10 19:06:18 +0200 (Fri, 10 Apr 2009)");

  script_name("LinPHA 1.3.4 Multiple Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with LinPHA
 and is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to LinPHA
 fails to properly sanitise user supplied input");

  script_tag(name:"impact", value:"Successful remote exploitation will
 let the attacker execute arbitrary code in the scope of the
 application. As a result the attacker may gain sensitive information
 and use it to redirect the user to any other malicious URL.");

  script_tag(name:"affected", value:"LinPHA 1.3.4 is vulnerable, other versions may also be affected");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34422");

  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("linpha_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("linpha/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
