###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_sql_inj_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Cacti SQL Injection Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806025");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-4634");
  script_bugtraq_id(75984);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-20 16:27:33 +0530 (Thu, 20 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Cacti SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Cacti and is
  prone to SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization of
  user-supplied input in graphs.php script via 'local_graph_id' parameter");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary SQL commands in the backend database, and
  disclose certain sensitive information.");

  script_tag(name:"affected", value:"Cacti version before 0.8.8e.");

  script_tag(name:"solution", value:"Upgrade to version 0.8.8e or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2577");
  script_xref(name:"URL", value:"http://www.cacti.net/release_notes_0_8_8e.php");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl");
  script_mandatory_keys("cacti/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!http_port = get_app_port(cpe:CPE))
  exit(0);

if (!cactiVer = get_app_version(cpe:CPE, port:http_port))
  exit(0);

if (version_is_less(version:cactiVer, test_version:"0.8.8e")) {
  report = report_fixed_ver(installed_version: cactiVer, fixed_version: "0.8.8e");
  security_message(data:report, port:http_port);
  exit(0);
}

exit(0);
