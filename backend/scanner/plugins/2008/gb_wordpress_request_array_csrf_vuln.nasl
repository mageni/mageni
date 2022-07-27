###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_request_array_csrf_vuln.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# WordPress _REQUEST array Cross Site Request Forgery (CSRF) Vulnerabilities.
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800140");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2008-5113");
  script_name("WordPress _REQUEST array Cross Site Request Forgery (CSRF) Vulnerability");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2008/11/14/1");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=504771");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary script code
  and can cause denial of service condition.");

  script_tag(name:"affected", value:"WordPress 2.6.3 and earlier.");

  script_tag(name:"insight", value:"The flaw is due to incorrect usage of _REQUEST super global array,
  which leads to cross site request forgery (CSRF) attacks via crafted cookies.");

  script_tag(name:"summary", value:"The host is installed with WordPress and is prone to Cross Site
  Request Forgery(CSRF) Vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to WordPress version 2.9.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version:ver, test_version:"2.6.3")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.9.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);