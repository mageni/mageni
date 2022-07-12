###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webmin_read_mail_module_info_disc_vuln_win.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Webmin Read Mail Module Information Disclosure Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811524");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2015-1377");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-17 12:05:05 +0530 (Mon, 17 Jul 2017)");
  script_name("Webmin Read Mail Module Information Disclosure Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Webmin and is prone
  to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in an unknown
  function of the component Read Mail Module. The manipulation with an unknown
  input leads to a information disclosure vulnerability (file).");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to read arbitrary files.");

  script_tag(name:"affected", value:"Webmin versions 1.720 and prior.");

  script_tag(name:"solution", value:"Upgrade to Webmin version 1.730 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.webmin.com/security.html");
  script_xref(name:"URL", value:"http://www.webmin.com/changes.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("webmin.nasl", "os_detection.nasl");
  script_mandatory_keys("webmin/installed", "Host/runs_windows");
  script_require_ports("Services/www", 10000, 20000);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wmport = get_app_port(cpe:CPE)){
 exit(0);
}

if(!wmver = get_app_version(cpe:CPE, port:wmport)){
 exit(0);
}

if(version_is_less(version:wmver, test_version:"1.730"))
{
  report = report_fixed_ver(installed_version:wmver, fixed_version:"1.730");
  security_message(data:report, port:wmport);
  exit(0);
}
exit(0);
