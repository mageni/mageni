###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotcms_v411_rem_sh_upl_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# dotCMS 4.1.1 Remote Shell Upload Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:dotcms:dotcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112089");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-20 11:29:18 +0200 (Fri, 20 Oct 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2017-11466");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("dotCMS 4.1.1 Remote Shell Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_detect.nasl");
  script_mandatory_keys("dotCMS/installed");

  script_tag(name:"summary", value:"dotCMS version 4.1.1 is prone to a remote shell upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Arbitrary file upload vulnerability in com/dotmarketing/servlets/AjaxFileUploadServlet.class allows remote authenticated administrators
to upload .jsp files to arbitrary locations via directory traversal sequences in the fieldName parameter to servlets/ajax_file_upload.");

  script_tag(name:"impact", value:"Remotely authenticated attackers might use this vulnerability to execute arbitrary code on the target.");

  script_tag(name:"affected", value:"dotCMS version 4.1.1.");

  script_tag(name:"solution", value:"Update to dotCMS version 4.2.0 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jul/33");
  script_xref(name:"URL", value:"https://github.com/dotCMS/core/issues/12131");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/143383/dotcms411-shell.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
