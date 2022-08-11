###############################################################################
# OpenVAS Vulnerability Test
# $Id: openoffice_CB-A08-0068.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# OpenOffice.org <= 2.4.1 vulnerability (Linux)
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
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
###############################################################################

CPE = "cpe:/a:openoffice:openoffice.org";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90029");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-09-09 22:57:12 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2152", "CVE-2008-3282");
  script_name("OpenOffice.org <= 2.4.1 vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_openoffice_detect_lin.nasl");
  script_mandatory_keys("OpenOffice/Linux/Ver");

  script_xref(name:"URL", value:"https://www.openoffice.org/security/cves/CVE-2008-2152.html");

  script_tag(name:"solution", value:"All OpenOffice.org users should upgrade to the latest version.");
  script_tag(name:"summary", value:"The remote host is probably affected by the vulnerabilities described in
  CVE-2008-2152 or CVE-2008-3282 on 64-bit platform's

  OpenOffice.org <= 2.4.1 vulnerability

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
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_is_less( version:version, test_version:"3.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.0" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );