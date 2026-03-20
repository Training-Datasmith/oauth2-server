<?php

declare (strict_types=1);
namespace League\O_Auth2\Server\Event_Emitting;

use League\Event\Event_Dispatcher;
use League\Event\Listener_Priority;
final class Event_Emitter extends Event_Dispatcher
{
    public function add_listener(string $event, callable $listener, int $priority = Listener_Priority::NORMAL): self
    {
        $this->subscribe_to($event, $listener, $priority);
        return $this;
    }
    public function emit(object $event): object
    {
        return $this->dispatch($event);
    }
}