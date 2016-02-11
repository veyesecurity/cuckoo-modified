# Copyright (C) 2015 vEyE Security Ltd., Yevgeniy Kulakov (yevgeniy@veye-security.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import boto
import boto.ec2
import boto.ec2.instance
import xmlrpclib
import socket
from time import sleep

from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class Aws(Machinery):
	"""Manage aws based sandboxes."""

	# Physical machine states.
	RUNNING = "running"
	STOPPED = "stopped"
	ERROR = "error"

	def _initialize_check(self):
		"""Ensures that credentials have been entered into the config file.
		@raise CuckooCriticalError: if no credentials were provided.
		"""

		if (len(self.options.aws.aws_secret_key) == 0 or \
			len(self.options.aws.aws_access_key_id) == 0 or \
			len(self.options.aws.aws_region) == 0 or \
			len(self.options.aws.aws_zone) == 0):
			raise CuckooCriticalError("AWS environment configuration is not complete, please add all the needed data!")

		self.inst = None
		self.vol = None

	def _get_machine(self, label):
		"""Retrieve all machine info given a machine's name.
		@param label: machine name.
		@return: machine dictionary (id, ip, platform, ...).
		@raises CuckooMachineError: if no machine is available with the given label.
		"""

		for m in self.machines():
			if label == m.label:
				return m

		raise CuckooMachineError("No machine with label: %s." % label)

	def start(self, label):
		"""Start an aws machine.
		@param label: aws machine name.
		@raise CuckooMachineError: if unable to start.
		"""
		# Check to ensure a given machine is running
		log.debug("Checking if machine %r is running.", label)
		status = self._status(label)
		if status == self.RUNNING:
			log.debug("Machine already running: %s.", label)

		elif status == self.STOPPED:
			ec2 = boto.ec2.connect_to_region(self.options.aws.aws_region, aws_secret_access_key = self.options.aws.aws_secret_key, aws_access_key_id = self.options.aws.aws_access_key_id)
			if self.options.aws.mode == 'replace':
				machine = self._get_machine(label)
				cuckoo_snap = ec2.get_all_snapshots(snapshot_ids = [machine.snapshot])[0]
				self.vol = cuckoo_snap.create_volume(self.options.aws.aws_zone, volume_type = 'gp2')
				log.debug("Creating clean volume...")
				while self.vol.status != 'available':
					sleep(2)
					self.vol.update()
				if self.vol.attach(label, '/dev/sda1'):
					log.debug("Attaching clean volume to %s..." % label)
					while self.vol.status == 'attaching':
						sleep(2)
						self.vol.update()
					self.inst = ec2.get_only_instances(instance_ids = [label])[0]
					log.debug("Starting machine %s..." % label)
					self.inst.start()
			elif self.options.aws.mode == 'reboot':
				self.inst = ec2.get_only_instances(instance_ids = [label])[0]
				log.debug("Starting machine %s..." % label)
				if self.inst:
					self.inst.start()
					sleep(15)
			else:
				raise CuckooMachineError("Unsuported machine mode: %s" % self.options.aws.mode)

			self._wait_status(label, self.RUNNING)
			log.info("Machine %s started successfully." % label)

		else:
			raise CuckooMachineError("Error occurred while starting: "
									 "%s (STATUS=%s)" % (label, status))

	def stop(self, label):
		"""Stops/reboots aws machine.
		@param label: aws machine name.
		@raise CuckooMachineError: if unable to stop/reboot.
		"""
		# Since we are 'stopping' a physical machine, it must
		# actually be rebooted to kick off the re-imaging process
		status = self._status(label)

		if status == self.RUNNING:
			if self.options.aws.mode == 'replace':
				log.info("Shutting down machine: %s.", label)
				self.inst.stop()
				self._wait_status(label, self.STOPPED)
				while self.inst.state != 'stopped':
					sleep(1)
					self.inst.update()
				log.debug("Detaching dirty volume...")
				if self.vol.detach():
					while self.vol.status != 'available':
						sleep(3)
						self.vol.update()
					
					sleep(2)

					if self.vol.delete():
						log.debug("Dirty volume deleted...")
						log.debug("Machine shutdown success: %s." % label)
						self.inst = None
						self.vol = None
						return
					else:
						log.debug("There was a problem deleted dirty volume at %s machine!" % label)
				else:
					log.debug("There was a problem detaching the volume at %s machine!" % label)
				log.debug("Shutdown of %s machine has failed!" % label)
			elif self.options.aws.mode == 'reboot':
				log.info("Rebooting the machine: %s.", label)
				if self.inst.reboot():
					sleep(30)
					log.info("Machine rebooted successfully: %s." % label)
				else:
					raise CuckooMachineError("Error rebooting the machine: %s (STATUS=%s)" % (label, status))
			else:
				raise CuckooMachineError("Unsuported machine mode: %s" % self.options.aws.mode)


	def _status(self, label):
		"""Gets current status of a aws machine.
		@param label: aws machine name.
		@return: status string.
		"""
		# For aws machines, the agent can either be contacted or not.
		# However, there is some information to be garnered from potential
		# exceptions.
		machine = self._get_machine(label)

		try:
			if self.inst == None:
				return self.STOPPED

			self.inst.update()
			if self.inst.state == 'pending':
				log.debug("Waiting a little bit for machine to get ready...")
				sleep(10)
				return self.STOPPED
			elif self.inst.state == 'running':
				log.debug("Getting status for machine: %s.", label)
				guest = GuestManager(machine.id, machine.ip, machine.platform)
				if not guest:
					sleep(10)
					guest = GuestManager(machine.id, machine.ip, machine.platform)
					if not guest:
						sleep(10)
						guest = GuestManager(machine.id, machine.ip, machine.platform)
						if not guest:
							raise CuckooMachineError("Unable to get status for machine: %s." % label)
				if  guest.server.get_status():
					return self.RUNNING
				return self.ERROR
			elif self.inst.state in ['terminated', 'stopped']:
				return self.STOPPED
			elif self.inst.state in ['shutting-down', 'stopping']:
				return self.RUNNING
			return self.STOPPED			
		except xmlrpclib.Fault as e:
			# Contacted Agent, but it threw an error.
			log.debug("Agent error: %s (%s) (Error: %s).",
					  machine.id, machine.ip, e)
			return self.ERROR
		except socket.error as e:
			# Could not contact agent.
			log.debug("Agent unresponsive: %s (%s) (Error: %s).",
					  machine.id, machine.ip, e)
			return self.STOPPED
	 	except Exception as e:
			# TODO Handle this better.
			log.debug("Received unknown exception: %s.", e)
			return self.ERROR

		return self.ERROR
