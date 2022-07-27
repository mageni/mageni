###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ghostscript_mult_bof_vuln_win.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# Ghostscript Multiple Buffer Overflow Vulnerabilities (Windows).
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900540");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0792", "CVE-2009-0196");
  script_bugtraq_id(34445, 34184);
  script_name("Ghostscript Multiple Buffer Overflow Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34292");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0983");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Apr/1022029.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ghostscript_detect_win.nasl");
  script_mandatory_keys("Ghostscript/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows the attacker to execute arbitrary code in
  the context of the affected application and can cause denial of service.");
  script_tag(name:"affected", value:"Ghostscript version 8.64 and prior on Windows.");
  script_tag(name:"insight", value:"These flaws arise due to,

  - a boundary error in the jbig2_symbol_dict.c() function in the JBIG2
    decoding library (jbig2dec) while decoding JBIG2 symbol dictionary
    segments.

  - multiple integer overflows in icc.c in the ICC Format library while
    processing malformed PDF and PostScript files with embedded images.");
  script_tag(name:"solution", value:"Upgrade to Ghostscript version 8.71 or later.");
  script_tag(name:"summary", value:"This host is installed with Ghostscript and is prone to
  Buffer Overflow Vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://ghostscript.com/releases/");
  exit(0);
}


include("version_func.inc");

ghostVer = get_kb_item("Ghostscript/Win/Ver");
if(!ghostVer){
  exit(0);
}

if(version_is_less_equal(version:ghostVer, test_version:"8.64")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
