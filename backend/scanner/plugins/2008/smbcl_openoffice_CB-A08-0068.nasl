# OpenVAS Vulnerability Test
# $Id: smbcl_openoffice_CB-A08-0068.nasl 11555 2018-09-22 15:24:22Z cfischer $
# Description: OpenOffice.org <= 2.4.1 vulnerability (Windows)
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
# Updated By Antu Sanadi <santu@secpod.com> on 16/09/2009
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# $Revision: 11555 $

if(description)
{

  script_oid("1.3.6.1.4.1.25623.1.0.90030");
  script_version("$Revision: 11555 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:24:22 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-09-09 22:57:12 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2152", "CVE-2008-3282");
  script_bugtraq_id(29622);
  script_name("OpenOffice.org <= 2.4.1 vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  script_tag(name:"solution", value:"All OpenOffice.org users should upgrade to the latest version:");
  script_tag(name:"summary", value:"The remote host is probably affected by the vulnerabilities described in
  CVE-2008-2152 or CVE-2008-3282 on 64-bit platform's

  Impact
   CVE-2008-2152
     Integer overflow in the rtl_allocateMemory function in
     sal/rtl/source/alloc_global.c in OpenOffice.org (OOo)
     2.0 through 2.4 allows remote attackers to execute
     arbitrary code via a crafted file that triggers a
     heap-based buffer overflow.
   CVE-2008-3282
     Integer overflow in the rtl_allocateMemory function
     in sal/rtl/source/alloc_global.c in the memory allocator
     in OpenOffice.org (OOo) 2.4.1, on 64-bit platforms, allows
     remote attackers to cause a denial of service (application
     crash) or possibly execute arbitrary code via a crafted
     document, related to a 'numeric truncation error, ' a
     different vulnerability than CVE-2008-2152.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

openVer = get_kb_item("OpenOffice/Win/Ver");
if(openVer != NULL)
{
  if(version_is_less_equal(version:openVer, test_version:"2.4.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
