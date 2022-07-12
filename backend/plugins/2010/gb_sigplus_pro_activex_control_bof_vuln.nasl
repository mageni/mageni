###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sigplus_pro_activex_control_bof_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# SigPlus Pro ActiveX Control 'LCDWriteString()' Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801252");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_cve_id("CVE-2010-2931");
  script_bugtraq_id(42109);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("SigPlus Pro ActiveX Control 'LCDWriteString()' Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40818");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60839");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14514");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sigplus_pro_activex_detect.nasl");
  script_mandatory_keys("SigPlus/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code on the system or cause the victim's browser to crash.");
  script_tag(name:"affected", value:"SigPlus Pro ActiveX control version 3.74");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in SigPlus.ocx when handling the
  'HexString' argument passed to the 'LCDWriteString()' method and can be
  exploited to cause a stack-based buffer overflow via an overly long string.");
  script_tag(name:"solution", value:"Upgrade to SigPlus Pro ActiveX control version 3.95 or later.");
  script_tag(name:"summary", value:"This host is installed with SigPlus Pro ActiveX Control and is
  prone to buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.topazsystems.com/software/download/sigplusactivex.htm");
  exit(0);
}


include("version_func.inc");

sigVer = get_kb_item("SigPlus/Ver");

if(sigVer)
{
  if(version_is_equal(version:sigVer, test_version:"3.74") ){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
