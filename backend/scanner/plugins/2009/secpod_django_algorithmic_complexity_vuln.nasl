###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_django_algorithmic_complexity_vuln.nasl 12694 2018-12-06 15:28:57Z cfischer $
#
# Django Forms Library Algorithmic Complexity Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900882");
  script_version("$Revision: 12694 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 16:28:57 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3695");
  script_bugtraq_id(36655);
  script_name("Django Forms Library Algorithmic Complexity Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36948/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2871");
  script_xref(name:"URL", value:"http://www.djangoproject.com/weblog/2009/oct/09/security/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a Denial of Service
  due to high CPU consumption via specially crafted email addresses or URLs.");

  script_tag(name:"affected", value:"Django version prior to 1.0 before 1.0.4 and 1.1 before 1.1.1.");

  script_tag(name:"insight", value:"The flaw is due to an error within the regular expressions used for
  validation of the 'EmailField' or 'URLField' form fields in Django's forms library.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Django version 1.0.4 or 1.1.1 or later.");

  script_tag(name:"summary", value:"The host is running Django and is prone to Algorithmic Complexity
  vulnerability.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

djangoVer = get_app_version(cpe: CPE);

if(djangoVer)
{
  if(version_in_range(version:djangoVer, test_version:"1.0", test_version2:"1.0.3")||
     version_is_equal(version:djangoVer, test_version:"1.1")){
    security_message(port:0);
  }
}
