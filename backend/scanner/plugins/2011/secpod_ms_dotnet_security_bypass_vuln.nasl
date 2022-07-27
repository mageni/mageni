###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_dotnet_security_bypass_vuln.nasl 12490 2018-11-22 13:45:33Z cfischer $
#
# Microsoft .NET Framework Security Bypass Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902518");
  script_version("$Revision: 12490 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-11-22 14:45:33 +0100 (Thu, 22 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_cve_id("CVE-2011-1271");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Microsoft .NET Framework Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://stackoverflow.com/questions/2135509/bug-only-occurring-when-compile-optimization-enabled/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow context-dependent attackers to bypass
  intended access restrictions.");

  script_tag(name:"affected", value:"Microsoft .NET Framework versions before 4 beta 2.");

  script_tag(name:"insight", value:"The flaw is due to an error in the JIT compiler, when
  'IsJITOptimizerDisabled' is set to false, fails to handle expressions
  related to null strings, which allows context-dependent attackers to bypass
  intended access restrictions in opportunistic circumstances by leveraging a crafted application.");

  script_tag(name:"solution", value:"Upgrade to Microsoft .NET Framework version 4 beta 2 or later.");

  script_tag(name:"summary", value:"The host is installed with Microsoft .NET Framework and is prone to
  security bypass vulnerability

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.902522.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.microsoft.com/net/download.aspx");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-044.nasl.