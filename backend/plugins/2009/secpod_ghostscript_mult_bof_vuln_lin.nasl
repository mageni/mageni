###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ghostscript_mult_bof_vuln_lin.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# Ghostscript Multiple Buffer Overflow Vulnerabilities (Linux).
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:ghostscript:ghostscript';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900542");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0792", "CVE-2009-0196");
  script_bugtraq_id(34445, 34184);
  script_name("Ghostscript Multiple Buffer Overflow Vulnerabilities (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ghostscript_detect_lin.nasl");
  script_mandatory_keys("Ghostscript/Linux/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34292");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0983");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Apr/1022029.html");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to execute arbitrary code in
  the context of the affected application and to cause denial of service.");
  script_tag(name:"affected", value:"Ghostscript version 8.64 and prior on Linux.");
  script_tag(name:"insight", value:"The flaws arise due to

  - A boundary error in the jbig2_symbol_dict.c() function in the JBIG2
    decoding library (jbig2dec) while decoding JBIG2 symbol dictionary
    segments.

  - multiple integer overflows in icc.c in the ICC Format library while
    processing malformed PDF and PostScript files with embedded images.");
  script_tag(name:"solution", value:"Upgrade to Ghostscript version 8.71 or later.");
  script_tag(name:"summary", value:"This host is installed with Ghostscript and is prone to
  Buffer Overflow Vulnerability.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://ghostscript.com/releases/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

ver = get_app_version(cpe:CPE);

if(version_is_less_equal(version:ver, test_version:"8.64")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"8.71");
  security_message(data:report);
  exit(0);
}

exit(99);
