###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_rtl_allocatememory_bof_vuln_lin.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# OpenOffice rtl_allocateMemory Heap Based BOF Vulnerability (Linux)
#
# Authors:      Chandan S <schandan@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800010");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-01 17:01:16 +0200 (Wed, 01 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2152");
  script_bugtraq_id(29622);
  script_name("OpenOffice rtl_allocateMemory Heap Based BOF Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30599");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2008-2152.html");
  script_xref(name:"URL", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=714");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rpms", "ssh/login/release");

  script_tag(name:"affected", value:"OpenOffice.org 2.x on Linux (Any).");
  script_tag(name:"insight", value:"The flaw is in alloc_global.c file in which rtl_allocateMemory function
  rounding up allocation requests to be aligned on a 8 byte boundary without
  checking the rounding results in an integer overflow condition.");
  script_tag(name:"summary", value:"The host has OpenOffice installed which is prone to heap based
  buffer overflow vulnerability.");
  script_tag(name:"solution", value:"Upgrade to OpenOffice 2.4.1.");
  script_tag(name:"impact", value:"Exploitation will result in buffer overflows via a specially crafted document
  and allow remote unprivileged user who provides a OpenOffice.org document that
  is opened by a local user to execute arbitrary commands on the system with the
  privileges of the user running OpenOffice.org.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

release = get_kb_item("ssh/login/release");
foreach item (get_kb_list("ssh/login/rpms"))
{
  # Exit if advisory based local check is available as they perform complete
  # rpm package comparison.
  # FixMe: Advisory local check is yet to be released for Fedora
  if((release =~ "^FC[7-9]") && (item =~ "(O|o)pen(O|o)ffice.*")) {
    report = string("Fedora advisory based local check is available to verify if the package is up-to-date as per the vendor advisory. Please run the Fedora Local Checks to confirm.");
    log_message(data:report);
    exit(0);
  }

  if(egrep(pattern:"^(O|o)pen(O|o)ffice.*?~([01]\..*|2\.([0-3][^0-9]|4(\.0)?[^.0-9]))", string:item)) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
