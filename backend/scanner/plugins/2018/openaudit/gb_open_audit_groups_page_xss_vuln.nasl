###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_audit_groups_page_xss_vuln.nasl 13716 2019-02-18 04:31:31Z ckuersteiner $
#
# Open-AudIT Community 'Groups Page' Cross Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:opmantek:open-audit";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813807");
  script_version("$Revision: 13716 $");
  script_cve_id("CVE-2018-14493");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 05:31:31 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-07-27 11:05:07 +0530 (Fri, 27 Jul 2018)");
  ##Not able to distinguish community editions
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Open-AudIT Community 'Groups Page' Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Open-AudIT
  and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient sanitization
  for the 'Name' field of an Groups page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Open-AudIT Community version 2.2.6.");

  script_tag(name:"solution", value:"No known solution is available as of 18th February, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name:"URL", value:"https://docs.google.com/document/d/1K3G6a8P_LhYdk5Ddn57Z2aDUpaGAS7I_F8lESVfSFfY/edit");
  script_xref(name:"URL", value:"https://opmantek.com");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_open_audit_detect.nasl");
  script_mandatory_keys("open-audit/detected");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version:version, test_version:"2.2.6")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None");
  security_message(data:report, port:port);
  exit(0);
}

exit(0);
