##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_python_mult_vuln_lin_900106.nasl 12491 2018-11-22 13:57:03Z cfischer $
#
# Python Multiple Vulnerabilities (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900106");
  script_version("$Revision: 12491 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-11-22 14:57:03 +0100 (Thu, 22 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_bugtraq_id(30491);
  script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142",
		"CVE-2008-3143", "CVE-2008-3144");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_name("Python Multiple Vulnerabilities (Linux)");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://bugs.python.org/issue2588");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2589");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2620");
  script_xref(name:"URL", value:"http://svn.python.org");

  script_tag(name:"summary", value:"The host is installed Python, which is prone to multiple vulnerabilities.

  This NVT has been replaced by various LSCs.");

  script_tag(name:"insight", value:"The flaws exist due to integer overflow in,

  - hashlib module, which can lead to an unreliable cryptographic digest results.

  - the processing of unicode strings.

  - the PyOS_vsnprintf() function on architectures that do not have a vsnprintf() function.

  - the PyOS_vsnprintf() function when passing zero-length strings can lead to memory corruption.");

  script_tag(name:"affected", value:"Python 2.5.2 and prior on Linux (All).");

  script_tag(name:"solution", value:"Fix is available in the SVN repository.");

  script_tag(name:"impact", value:"Successful exploitation could potentially causes attackers to
  execute arbitrary code or create a denial of service condition.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

exit(66); ## Addressed by various LSCs