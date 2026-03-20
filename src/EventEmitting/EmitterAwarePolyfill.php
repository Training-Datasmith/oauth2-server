<?php

declare (strict_types=1);
namespace League\O_Auth2\Server\Event_Emitting;

use League\Event\Listener_Registry;
use Psr\Event_Dispatcher\Event_Dispatcher_Interface;
trait Emitter_Aware_Polyfill
{
    private Event_Emitter $emitter;
    public function get_emitter(): Event_Emitter
    {
        return $this->emitter ??= new Event_Emitter();
    }
    public function set_emitter(Event_Emitter $emitter): self
    {
        $this->emitter = $emitter;
        return $this;
    }
    public function get_event_dispatcher(): Event_Dispatcher_Interface
    {
        return $this->get_emitter();
    }
    public function get_listener_registry(): Listener_Registry
    {
        return $this->get_emitter();
    }
}