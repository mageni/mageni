###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_vuln_win.nasl 12604 2018-11-30 15:07:33Z cfischer $
#
# Apple QuickTime Multiple Arbitrary Code Execution Vulnerabilities (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800102");
  script_version("$Revision: 12604 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 16:07:33 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-09-26 14:12:58 +0200 (Fri, 26 Sep 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-1581", "CVE-2008-1582", "CVE-2008-1583",
                "CVE-2008-1584", "CVE-2008-1585");
  script_bugtraq_id(29619);
  script_name("Apple QuickTime Multiple Arbitrary Code Execution Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"affected", value:"Apple QuickTime before 7.5 on Windows (Any).");

  script_tag(name:"insight", value:"The flaws are due to,

  - boundary error when parsing packed scanlines from a PixData
    structure in a PICT file which can be exploited via specially crafted
    PICT file.

  - memory corruption issue in AAC-encoded media content can be
    exploited via a specially crafted media file.

  - error in the handling of PICT files or Indeo video codec content that
    can be exploited via a specially crafted PICT file or movie file with
    Indeo video codec content respectively.

  - error in the handling of file URLs that can be exploited by making user
    to play maliciously crafted QuickTime content.");

  script_tag(name:"summary", value:"The host is installed with Apple QuickTime which is prone to
  Multiple Arbitrary Code Execution Vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.5 or later.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to execute arbitrary
  code or unexpected application termination.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1991");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29293");
  script_xref(name:"URL", value:"http://www.nruns.com/security_advisory_quicktime_arbitrary_code_execution.php");

  exit(0);
}

if(egrep(pattern:"^([0-6]\..*|7\.([0-4](\..*)?))$",
         string:get_kb_item("QuickTime/Win/Ver"))){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
