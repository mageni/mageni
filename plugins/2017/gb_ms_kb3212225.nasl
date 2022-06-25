###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Mac 2011 Multiple Vulnerabilities (KB3212225)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811812");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-8567", "CVE-2017-8631", "CVE-2017-8632", "CVE-2017-8676");
  script_bugtraq_id(100719, 100751, 100734, 100755);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 08:47:40 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Office Mac 2011 Multiple Vulnerabilities (KB3212225)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3212225");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists when,

  - Microsoft Office software fails to properly handle objects in memory.

  - The Windows Graphics Device Interface (GDI) improperly handles objects in
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to run arbitrary code in the context of the current user,
  perform actions in the security context of the current user and retrieve
  information from a targeted system.");

  script_tag(name:"affected", value:"Microsoft Excel for Mac 2011

  Microsoft Office for Mac 2011");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3212225");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");


if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer =~ "^(14\.)")
{
  if(version_is_less(version:offVer, test_version:"14.1.7"))
  {
    report = 'File version:     ' + offVer   + '\n' +
             'Vulnerable range: 14.1.0 - 14.1.6' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);
