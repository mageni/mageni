###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wpjobboard_mul_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# WpJobBoard Multiple Cross Site Web Vulnerabilities
#
# Authors:
# Tameem Eissa <teissa@greenbone.net>
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

CPE = "cpe:/a:wpjobboard:wpjobboard";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107235");
  script_version("$Revision: 11863 $");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-06 20:31:53 +0530 (Wed, 06 Sep 2017)");
  script_name("WpJobBoard Multiple Cross Site Web Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with WpJobBoard and is prone to multiple cross-site web vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities are located in the query and id parameters of the wpjb-email, wpjb-job, wpjb-application and wpjb-membership modules.");

  script_tag(name:"impact", value:"Remote attackers are able to inject own malicious script code to hijack admin session credentials
via backend or to manipulate the backend on client-side performed requests. Attack Vector: Non-persistent.");

  script_tag(name:"affected", value:"WPJobBoard - Wordpress Plugin 4.4.4 and 4.5.1.");

  script_tag(name:"solution", value:"Updates are available. Check for fixes supplied by the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Sep/0");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_wpjobboard_detect.nasl");
  script_mandatory_keys("wpjobboard/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if (version_is_equal(version:ver, test_version:"4.4.4") || version_is_equal(version:ver, test_version:"4.5.1")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"Check for fixes supplied by the vendor");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
