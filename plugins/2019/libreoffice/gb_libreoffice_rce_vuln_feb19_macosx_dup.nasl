# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814904");
  script_version("2019-12-03T13:45:27+0000");
  script_cve_id("CVE-2018-16858");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-12-03 13:45:27 +0000 (Tue, 03 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-02-07 10:41:49 +0530 (Thu, 07 Feb 2019)");
  script_name("LibreOffice Remote Code Execution Vulnerability Feb19 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with LibreOffice and
  is prone to remote code execution vulnerability.

  This VT is a duplicate of VT 'LibreOffice Remote Code Execution Vulnerability Feb19 (Mac OS X)'
  (OID: 1.3.6.1.4.1.25623.1.0.814905).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the file 'pydoc.py' in
  LibreOffice's Python interpreter which accepts and executes arbitrary commands.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and traverse directories.");

  script_tag(name:"affected", value:"LibreOffice before 6.0.7 and 6.1.3 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version 6.0.7 or
  6.1.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2018-16858/");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_libreoffice_detect_macosx.nasl");
  script_mandatory_keys("LibreOffice/MacOSX/Version");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
