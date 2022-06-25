###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libreoffice_readjpeg_heap_bof_vuln_win.nasl 11816 2018-10-10 10:42:56Z mmartin $
#
# LibreOffice 'ReadJPEG' Function Heap Buffer Overflow Vulnerability (Windows)
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

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811583");
  script_version("$Revision: 11816 $");
  script_cve_id("CVE-2017-8358");
  script_bugtraq_id(98395);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 12:42:56 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-18 12:11:47 +0530 (Fri, 18 Aug 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("LibreOffice 'ReadJPEG' Function Heap Buffer Overflow Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with LibreOffice
  and is prone to a heap buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a heap-based buffer
  overflow error related to the 'ReadJPEG' function in
  'vcl/source/filter/jpeg/jpegc.cxx' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to execute arbitrary code within the context of the affected
  application. Failed exploit attempts will result in a denial-of-service
  condition.");

  script_tag(name:"affected", value:"LibreOffice versions 5.2.6 and earlier
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version
  5.2.7 or later.   Note: 5.2 series end of life is June 4, 2017");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://github.com/LibreOffice/core/commit/6e6e54f944a5ebb49e9110bdeff844d00a96c56c");
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

if(version_is_less(version:libreVer, test_version:"5.2.7"))
{
  report = report_fixed_ver(installed_version:libreVer, fixed_version:"Upgrade to 5.2.7 or later");
  security_message(data:report);
  exit(0);
}
