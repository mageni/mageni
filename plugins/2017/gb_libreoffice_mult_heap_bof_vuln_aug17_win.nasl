###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libreoffice_mult_heap_bof_vuln_aug17_win.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# LibreOffice Multiple Heap Buffer Overflow Vulnerabilities Aug17 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811715");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-7870", "CVE-2016-10327");
  script_bugtraq_id(97667);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-23 10:45:49 +0530 (Wed, 23 Aug 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("LibreOffice Multiple Heap Buffer Overflow Vulnerabilities Aug17 (Windows)");

  script_tag(name:"summary", value:"The host is installed with LibreOffice
  and is prone to multiple heap buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Windows Metafiles (WMF) can contain polygons which under certain circumstances
    when processed (split) can result in output polygons which have too many points
    to be represented by LibreOffice's internal polygon class.

  - Enhanced Metafiles (EMF) can contain bitmap data preceded by a header and a
    field with in that header which states the offset from the start of the header
    to the bitmap data. An emf can be crafted to provide an illegal offset.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to execute arbitrary code within the context of the affected
  application. Failed exploit attempts will result in a denial-of-service
  condition.");

  script_tag(name:"affected", value:"LibreOffice versions prior to version 5.2.5
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version 5.2.5 or
  5.3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2017-7870");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2016-10327");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  script_xref(name:"URL", value:"http://www.libreoffice.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!libreVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:libreVer, test_version:"5.2.5"))
{
  report = report_fixed_ver(installed_version:libreVer, fixed_version:"Upgrade to 5.2.5 or later");
  security_message(data:report);
  exit(0);
}
