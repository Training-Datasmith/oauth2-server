<?php

declare (strict_types=1);
namespace League\O_Auth2\Server\Event_Emitting;

interface Emitter_Aware_Interface
{
    public function get_emitter(): Event_Emitter;
    public function set_emitter(Event_Emitter $emitter): self;
}