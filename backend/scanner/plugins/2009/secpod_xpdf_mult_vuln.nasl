###############################################################################
# OpenVAS Vulnerability Test
#
# Xpdf Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

CPE = 'cpe:/a:foolabs:xpdf';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900457");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-05-06 08:04:28 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(34568, 34791);
  script_cve_id("CVE-2009-0195", "CVE-2009-0166", "CVE-2009-0147", "CVE-2009-0146",
                "CVE-2009-1183", "CVE-2009-1182", "CVE-2009-1181", "CVE-2009-1179",
                "CVE-2009-0800", "CVE-2009-1180", "CVE-2009-0799", "CVE-2009-0165");
  script_name("Xpdf Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_xpdf_detect.nasl");
  script_mandatory_keys("Xpdf/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft a malicious PDF File and
  execute arbitrary codes into the context of the affected application to cause
  denial of service attacks, buffer overflow attacks, remote code executions etc.");
  script_tag(name:"affected", value:"Xpdf version 3.02 and prior on Linux.");
  script_tag(name:"insight", value:"- Integer overflow in Xpdf JBIG2 Decoder which allows the attacker create a
  malicious crafted PDF File and causes code execution.

  - Flaws in Xpdf JBIG2 Decoder which causes buffer overflow, freeing of
  arbitrary memory causing Xpdf application to crash.");
  script_tag(name:"solution", value:"Apply Xpdf v3.02 pl3 patch.");
  script_tag(name:"summary", value:"The PDF viewer Xpdf is prone to multiple vulnerabilities on Linux
  systems that can lead to arbitrary code execution.");
  script_tag(name:"vuldetect", value:"This test uses the xpdf detection results and checks version of each binary
  found on the target system. Version 3.02 and prior will raise a security alert.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34755");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495896");
  script_xref(name:"URL", value:"http://www.redhat.com/support/errata/RHSA-2009-0430.html");
  script_xref(name:"URL", value:"ftp://ftp.foolabs.com/pub/xpdf/xpdf-3.02pl3.patch");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:ver, test_version:"3.02")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"3.02 pl3");
  security_message(data:report);
  exit(0);
}

exit(99);