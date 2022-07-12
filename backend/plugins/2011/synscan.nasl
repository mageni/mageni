###############################################################################
# OpenVAS Vulnerability Test
# $Id: synscan.nasl 12014 2018-10-22 10:01:47Z mmartin $
#
# Wrapper for calling built-in NVT "synscan" which was previously
# a binary ".nes".
#
# Authors:
# Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11219");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12014 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 12:01:47 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-14 10:12:23 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SYN Scan");
  script_tag(name:"qod_type", value:"general_note");
  script_category(ACT_SCANNER);
  script_family("Port scanners");
  script_copyright("Copyright (C) Renaud Deraison <deraison@cvs.nessus.org>");
  script_tag(name:"summary", value :
"This plugins performs a supposedly fast SYN port scan.
It does so by computing the RTT (round trip time) of the packets
coming back and forth between the scanner and the target,
then it uses that to quickly send SYN packets to the remote host.");

  exit(0);
}

plugin_run_synscan();

