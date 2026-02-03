############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2026 Belledonne Communications, Grenoble France
#
############################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
############################################################################

target_sources(flexisip PRIVATE
	Arg.h
	ArgException.h
	ArgTraits.h
	COPYING
	CmdLine.h
	CmdLineInterface.h
	CmdLineOutput.h
	Constraint.h
	DocBookOutput.h
	HelpVisitor.h
	IgnoreRestVisitor.h
	MultiArg.h
	MultiSwitchArg.h
	OptionalUnlabeledTracker.h
	StandardTraits.h
	StdOutput.h
	SwitchArg.h
	UnlabeledMultiArg.h
	UnlabeledValueArg.h
	ValueArg.h
	ValuesConstraint.h
	VersionVisitor.h
	Visitor.h
	XorHandler.h
	ZshCompletionOutput.h
)