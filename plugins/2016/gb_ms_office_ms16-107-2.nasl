###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office 2013 APP-V ASLR Bypass Vulnerability (3118268)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112000");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0137");
  script_bugtraq_id(92785);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-08-18 14:45:19 +0200 (Fri, 18 Aug 2017)");
  script_name("Microsoft Office 2013 APP-V ASLR Bypass Vulnerability (3118268)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3118268");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-107");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-107.

  This VT has been replaced by 'Microsoft Office Suite Remote Code Execution Vulnerabilities (3185852)' (1.3.6.1.4.1.25623.1.0.807361).");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check if an
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"An information disclosure vulnerability exists in the way
  that the Click-to-Run (C2R) components handle objects in memory,
  which could lead to an Address Space Layout Randomization (ASLR) bypass.");

  script_tag(name:"impact", value:"Successful exploitation could allow
  remote code execution if a user opens a specially crafted Microsoft Office file.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # this NVT is deprecated since it has been covered already by gb_ms_office-ms16-107.nasl