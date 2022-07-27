###############################################################################
# OpenVAS Vulnerability Test
#
# Django Directory Traversal Vulnerability (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:django_project:django";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800924");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2659");
  script_bugtraq_id(35859);
  script_name("Django Directory Traversal Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36137");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=539134");
  script_xref(name:"URL", value:"http://www.djangoproject.com/weblog/2009/jul/28/security/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker launch directory traversal
  attack and read arbitrary files via crafted URLs.");
  script_tag(name:"affected", value:"Django 0.96 before 0.96.4 and 1.0 before 1.0.3 on Linux");
  script_tag(name:"insight", value:"Admin media handler in core/servers/basehttp.py does not properly map
  URL requests to expected 'static media files, ' caused via a
  carefully-crafted URL which can cause the development server to serve any
  file to which it has read access.");
  script_tag(name:"solution", value:"Upgrade to Django 0.96.4 or 1.0.3 later.");
  script_tag(name:"summary", value:"This host has Django installed and is prone to Directory Traversal
  Vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!djangoVer = get_app_version(cpe: CPE))
  exit(0);

if(version_is_less(version:djangoVer, test_version:"0.96.4") ||
   version_in_range(version:djangoVer, test_version:"1.0",
                                      test_version2:"1.0.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
