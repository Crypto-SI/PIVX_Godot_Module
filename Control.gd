extends Control

onready var PIVX = preload("res://PIVX/bin/PIVX.gdns").new()

func _on_Button_pressed():
	PIVX.newPrivateKey()
	print(PIVX.getAddress())
